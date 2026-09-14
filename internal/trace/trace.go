// Package trace lets code inside this module watch the padded sealer at work.
// It is internal, so no caller of the library can install a hook.
package trace

// Event is one step of sealing a padded stream.
type Event struct {
	// Step is "header written", "chunk 0 created, length blank",
	// "chunk 0 length set", "sealing" (just before Seal) or "sealed" (just
	// after).
	Step string

	Index    uint64 // the chunk a sealing step concerns
	Final    bool   // that chunk is the last of the stream
	Sealed   bool   // Data and Tag were taken after Seal
	HeldBack bool   // chunk 0 waited for the payload length and is sealed after the others
	Before   uint64 // for chunk 0: how many chunks were already sealed

	// Data is the header, the frame, or chunk 0's bytes up to 4 payload bytes
	// past the frame. Tag is the 16-byte Poly1305 tag, nil before Seal
	// computes it.
	Data []byte
	Tag  []byte
}

// Hook is called, when non-nil, at each step with copies of the bytes
// involved. Those include the frame, which carries the payload length padding
// exists to hide, and payload bytes, so only debugging code should set it.
var Hook func(Event)
