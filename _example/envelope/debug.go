package main

// Debug output for the upload server. The lines about a padded stream come
// from inside the envelope package through a module-internal hook, so they
// show the real bytes rather than a reconstruction.

import (
	"encoding/binary"
	"log"

	"github.com/pilinux/crypt/envelope"
	"github.com/pilinux/crypt/internal/trace"
)

// installDebugHook logs how a padded stream's header, chunk 0 and last chunk
// are built and sealed. It prints the payload length and payload bytes: fine
// for a demo, never for a real server.
func installDebugHook() {
	trace.Hook = func(ev trace.Event) {
		switch ev.Step {
		case "header written":
			// version(1) || saltLen(1) || salt(16) || chunkSize(4) || noncePrefix(15)
			log.Printf("[debug] header written: % x (chunk size %d)", ev.Data, binary.BigEndian.Uint32(ev.Data[18:22]))
		case "sealing", "sealed":
			logSeal(ev)
		default:
			// the frame alone: version(1) || realLen(8)
			log.Printf("[debug] %s: % x (realLen %d)", ev.Step, ev.Data, binary.BigEndian.Uint64(ev.Data[1:9]))
		}
	}
}

// logSeal prints chunk 0 or the last chunk just before or just after Seal.
// After Seal the bytes are ciphertext, and only then is there a tag.
func logSeal(ev trace.Event) {
	when, enc := "before seal", ""
	if ev.Sealed {
		when, enc = "after seal", ", encrypted"
	}
	last := ""
	if ev.Final {
		last = " (last chunk)"
	}
	log.Printf("[debug] chunk %d%s, %s", ev.Index, last, when)

	if ev.Index == 0 {
		switch {
		case !ev.Sealed:
		case ev.HeldBack && ev.Before == 0:
			log.Printf("[debug]   sealed once, and it is the only chunk: held back until the length was known")
		case ev.HeldBack:
			log.Printf("[debug]   sealed once, last: after the other %d chunks, since the length was only known at the end", ev.Before)
		default:
			log.Printf("[debug]   sealed once, first: the length was known before any chunk was sealed")
		}
		log.Printf("[debug]   bytes 0-8, before the payload%s: % x", enc, ev.Data[:9])
		if len(ev.Data) > 9 {
			log.Printf("[debug]   bytes 9-%d, first payload bytes%s: % x", len(ev.Data)-1, enc, ev.Data[9:])
		} else {
			log.Printf("[debug]   no payload bytes: the payload is empty")
		}
	}

	if ev.Tag == nil {
		log.Printf("[debug]   tag: none yet, Seal computes it")
	} else {
		log.Printf("[debug]   tag: % x", ev.Tag)
	}
}

// logChunks reports how many chunks a finished object holds: on disk every
// chunk but the last is chunkSize+TagSize bytes, the last at least TagSize.
func logChunks(id string, sealed int64) {
	if trace.Hook == nil {
		return // -debug is off
	}
	per := int64(chunkSize + envelope.TagSize)
	chunks := (sealed - envelope.StreamHeaderSize + per - 1) / per
	log.Printf("[debug] %s: %d bytes on disk, %d chunks (chunk size %d)", id, sealed, chunks, chunkSize)
}
