// Package main - example usage of the envelope encryption scheme.
//
// This program is intentionally verbose: it dumps every intermediate value
// (keys, salt, nonce, AEAD ciphertext, tag, plaintext) so you can watch the
// envelope scheme work end to end and verify the on-the-wire layout:
//
//	version(1) || saltLen(1) || salt || XChaCha20-Poly1305(nonce || ciphertext || tag)
//
// The header (version, saltLen, salt) is authenticated as AEAD additional
// data, together with any caller-supplied AAD (see the context-binding
// section below).
//
// The last section switches to the streaming API, which seals a file too big
// for memory as a chain of chunks:
//
//	version(1) || saltLen(1) || salt || chunkSize(4) || noncePrefix(15) || chunk...
//
// A sealed stream still reveals the exact plaintext length, so the section
// after that pads the payload before sealing:
//
//	version(1) || realLen(8) || payload || zero padding   (all inside the stream)
//
// Padding needs that length before the first chunk is sealed, which an HTML
// multipart upload cannot supply. The last section shows the way around it:
// seal the upload unpadded, since that needs no length at all, and pad it in a
// background pass once the length is known.
//
// Run with -serve to skip the demos and start the upload server in server.go
// instead, for trying the same flow by hand with a real file:
//
//	go run ./_example/envelope -serve 127.0.0.1:8080
//
// -max raises or removes the upload cap and -dir picks the storage directory,
// which is what a multi-gigabyte test needs: the library has no size ceiling,
// but a demo server with a default cap and a temp dir does.
//
//	go run ./_example/envelope -serve 127.0.0.1:8080 -max 0 -dir /tmp/enc
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"

	"github.com/pilinux/crypt"
	"github.com/pilinux/crypt/envelope"
)

func main() {
	addr := flag.String("serve", "", "run the upload server on this address instead of the demos, e.g. 127.0.0.1:8080")
	dir := flag.String("dir", "", "where the server keeps ciphertext (default: a fresh temp dir)")
	limit := flag.Int64("max", defaultMaxUpload, "largest upload the server accepts, in bytes; 0 for no limit")
	flag.Parse()
	if *addr != "" {
		if err := serve(*addr, *dir, *limit); err != nil {
			fmt.Println("server:", err)
			os.Exit(1)
		}
		return
	}

	// The application secret, typically read from an env var such as
	// ENCRYPTION_SECRET. It must be at least envelope.MinSecretLength bytes of
	// machine-generated randomness (e.g. `openssl rand -hex 32`), never a
	// human-chosen passphrase: DeriveKEK applies no password stretching.
	secret := "0123456789abcdef0123456789abcdef01234567"

	section("0. Scheme parameters")
	fmt.Printf("  KeySize   = %d bytes\n", envelope.KeySize)
	fmt.Printf("  SaltSize  = %d bytes\n", envelope.SaltSize)
	fmt.Printf("  NonceSize = %d bytes (XChaCha20-Poly1305)\n", envelope.NonceSize)
	fmt.Printf("  TagSize   = %d bytes (Poly1305)\n", envelope.TagSize)
	fmt.Printf("  secret    = %q (len=%d, min=%d)\n", secret, len(secret), envelope.MinSecretLength)

	// Configure the scheme with app-specific HKDF domain-separation labels.
	// Pin these in your own source; changing them orphans already-sealed data.
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
	})

	// 1. Derive the key-encryption key (KEK) from the secret.
	section("1. Derive KEK (HKDF-SHA256 over the secret)")
	kek, err := scheme.DeriveKEK(secret)
	if err != nil {
		fmt.Println("DeriveKEK:", err)
		return
	}
	dumpBytes("kek", kek)

	// 2. Generate the master key once and store it wrapped (KEK-encrypted).
	section("2. Generate master key (DEK) and wrap it under the KEK")
	masterKey, err := envelope.GenerateMasterKey()
	if err != nil {
		fmt.Println("GenerateMasterKey:", err)
		return
	}
	dumpBytes("masterKey (plaintext DEK)", masterKey)

	wrapped, err := envelope.WrapKey(kek, masterKey)
	if err != nil {
		fmt.Println("WrapKey:", err)
		return
	}
	dumpBytes("wrapped master key (persist this)", wrapped)
	// The blob is raw bytes; base64 is the form that goes into a config file,
	// an env var or a database column.
	fmt.Printf("  %-34s %s\n", "wrapped master key (base64):", (&crypt.Encoder{}).ToBase64Std(wrapped))
	// WrapKey uses XChaCha20-Poly1305 with the nonce prepended, so the wrapped
	// blob is nonce || ciphertext || tag (no envelope header).
	dumpAEAD("wrapped", wrapped)

	// ... later, on startup, recover the master key from storage.
	section("3. Unwrap master key on startup")
	masterKey, err = envelope.UnwrapKey(kek, wrapped)
	if err != nil {
		fmt.Println("UnwrapKey:", err)
		return
	}
	dumpBytes("masterKey (recovered)", masterKey)

	// 4. Seal and open a string, dumping the full envelope layout.
	section("4. Seal a string")
	plain := "attack at dawn"
	fmt.Printf("  plaintext (string) = %q\n", plain)
	fmt.Printf("  plaintext (bytes)  = %x (len=%d)\n", []byte(plain), len(plain))

	token, err := scheme.SealString(masterKey, plain)
	if err != nil {
		fmt.Println("SealString:", err)
		return
	}
	fmt.Printf("  sealed token (base64) = %s (len=%d)\n", token, len(token))
	dumpEnvelope("sealed token", token)

	section("5. Open the string")
	plaintext, err := scheme.OpenString(masterKey, token)
	if err != nil {
		fmt.Println("OpenString:", err)
		return
	}
	fmt.Printf("  opened (bytes)  = %x (len=%d)\n", []byte(plaintext), len(plaintext))
	fmt.Printf("  opened (string) = %q\n", plaintext)
	fmt.Printf("  round-trip ok   = %t\n", plaintext == plain)

	// 6. Seal the same plaintext again to prove the salt/nonce differ per item.
	section("6. Seal the same plaintext twice -> different envelope")
	token2, err := scheme.SealString(masterKey, plain)
	if err != nil {
		fmt.Println("SealString:", err)
		return
	}
	dumpEnvelope("token (attempt #2)", token2)
	fmt.Printf("  tokens differ = %t (fresh salt + nonce each seal)\n", token != token2)

	// 7. Seal and open a signed integer. The value is encoded as fixed-width
	// 8-byte big-endian before sealing, so every int64 token has the same
	// length and the token length cannot leak the magnitude of the value.
	section("7. Seal / open an int64 (fixed-width 8-byte encoding)")
	intToken, err := scheme.SealInt64(masterKey, 42)
	if err != nil {
		fmt.Println("SealInt64:", err)
		return
	}
	fmt.Printf("  int token (base64) = %s\n", intToken)
	dumpEnvelope("int token", intToken)
	n, err := scheme.OpenInt64(masterKey, intToken)
	if err != nil {
		fmt.Println("OpenInt64:", err)
		return
	}
	fmt.Printf("  opened int64 = %d\n", n)

	// 8. Bind a token to its context with AAD so an attacker who can write to
	// the datastore cannot swap valid tokens between rows or fields.
	section("8. Context binding with AAD")
	aad := []byte("user:42:email")
	fmt.Printf("  aad = %q (authenticated, not encrypted, not stored)\n", aad)
	boundToken, err := scheme.SealStringAAD(masterKey, "alice@example.com", aad)
	if err != nil {
		fmt.Println("SealStringAAD:", err)
		return
	}
	dumpEnvelope("bound token", boundToken)
	bound, err := scheme.OpenStringAAD(masterKey, boundToken, aad)
	if err != nil {
		fmt.Println("OpenStringAAD:", err)
		return
	}
	fmt.Printf("  opened with correct aad   = %q\n", bound)
	_, err = scheme.OpenStringAAD(masterKey, boundToken, []byte("user:7:email"))
	fmt.Printf("  open with wrong aad fails = %t (%v)\n", err != nil, err)
	_, err = scheme.OpenString(masterKey, boundToken)
	fmt.Printf("  open with no aad fails    = %t (%v)\n", err != nil, err)

	// 9. Seal a file that does not fit in memory, chunk by chunk.
	if err := streamDemo(masterKey); err != nil {
		fmt.Println("stream demo:", err)
		return
	}

	// 10. Hide the plaintext length by padding before sealing.
	if err := paddingDemo(masterKey); err != nil {
		fmt.Println("padding demo:", err)
		return
	}

	// 11. Seal an upload of unknown length, then pad it out of band.
	if err := deferredPaddingDemo(masterKey); err != nil {
		fmt.Println("deferred padding demo:", err)
		return
	}

	// 12. Fingerprint a payload and mint a random file ID.
	section("12. Helpers")
	fmt.Println("  sha256:", envelope.Sha256Hex([]byte(plain)))
	id, err := envelope.RandomHex(16)
	if err != nil {
		fmt.Println("RandomHex:", err)
		return
	}
	fmt.Println("  random id:", id)
}

// section prints a labeled divider so the debug output is easy to scan.
func section(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
}

// dumpBytes prints a labeled byte slice with its length and hex encoding.
func dumpBytes(label string, b []byte) {
	fmt.Printf("  %-34s len=%3d  %s\n", label+":", len(b), hex.EncodeToString(b))
}

// dumpAEAD splits a raw XChaCha20-Poly1305 blob (nonce || ciphertext || tag,
// nonce prepended) into its parts and prints each one.
func dumpAEAD(label string, aead []byte) {
	if len(aead) < envelope.NonceSize+envelope.TagSize {
		fmt.Printf("  %s: too short to be an AEAD blob (len=%d)\n", label, len(aead))
		return
	}
	nonce := aead[:envelope.NonceSize]
	body := aead[envelope.NonceSize:]
	ciphertext := body[:len(body)-envelope.TagSize]
	tag := body[len(body)-envelope.TagSize:]

	fmt.Printf("  %s AEAD breakdown (nonce || ciphertext || tag):\n", label)
	dumpBytes("  nonce", nonce)
	dumpBytes("  ciphertext", ciphertext)
	dumpBytes("  tag", tag)
}

// dumpEnvelope base64-decodes a sealed token and prints the full on-the-wire
// envelope layout: version, salt length, salt, then the AEAD breakdown.
func dumpEnvelope(label, token string) {
	blob, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		fmt.Printf("  %s: not valid base64: %v\n", label, err)
		return
	}
	dumpBytes(label+" (blob)", blob)

	if len(blob) < 2 {
		fmt.Printf("  %s: too short to be an envelope (len=%d)\n", label, len(blob))
		return
	}
	version := blob[0]
	saltLen := int(blob[1])
	fmt.Printf("  %s envelope breakdown:\n", label)
	fmt.Printf("    version = 0x%02x\n", version)
	fmt.Printf("    saltLen = %d\n", saltLen)

	if len(blob) < 2+saltLen {
		fmt.Printf("    (truncated: blob shorter than declared salt)\n")
		return
	}
	salt := blob[2 : 2+saltLen]
	aead := blob[2+saltLen:]
	dumpBytes("  salt", salt)
	dumpAEAD("  ", aead)
}

// streamDemo shows the chunked streaming API on a file larger than one chunk.
// The plaintext is never held in memory as a whole: only one chunk at a time
// is buffered, so the same code handles a 100 GB file.
func streamDemo(masterKey []byte) error {
	// Same labels as above (so the same keys), but a small chunk size to keep
	// the demo file small while still producing several chunks. Production
	// code can leave ChunkSize unset and get envelope.DefaultChunkSize (1 MiB).
	const chunkSize = 256 << 10
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
		ChunkSize:   chunkSize,
	})

	dir, err := os.MkdirTemp("", "crypt-envelope-stream-")
	if err != nil {
		return err
	}
	fmt.Println("Temp dir:", dir)
	defer func() { _ = os.RemoveAll(dir) }()

	// 1 MiB plus a remainder, so the stream ends on a short chunk.
	payload := make([]byte, 1<<20+12345)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	plainPath := filepath.Join(dir, "large.bin")
	if err := os.WriteFile(plainPath, payload, 0o600); err != nil {
		return err
	}

	section("9. Stream a large file (chunked, constant memory)")
	fmt.Printf("  chunk size = %d bytes\n", chunkSize)
	fmt.Printf("  plaintext  = %s (%d bytes)\n", filepath.Base(plainPath), len(payload))
	fmt.Printf("  sha256     = %s\n", envelope.Sha256Hex(payload))

	// Seal: the file name doubles as context, so a sealed file cannot be
	// swapped for another one under the same master key.
	sealedPath := filepath.Join(dir, "large.bin.enc")
	aad := []byte("large.bin")
	// SealFileAAD takes the destination first, like io.Copy; it refuses to
	// overwrite an existing file, so a mixed-up order cannot destroy the source.
	n, err := scheme.SealFileAAD(masterKey, sealedPath, plainPath, aad)
	if err != nil {
		return err
	}
	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		return err
	}
	chunks := (len(payload) + chunkSize - 1) / chunkSize
	fmt.Printf("  sealed     = %s (%d bytes, +%d for %d chunks + header)\n",
		filepath.Base(sealedPath), len(sealed), len(sealed)-int(n), chunks)
	dumpStreamHeader(sealed)

	// Open it back and compare fingerprints end to end.
	openedPath := filepath.Join(dir, "large.out")
	if _, err := scheme.OpenFileAAD(masterKey, openedPath, sealedPath, aad); err != nil {
		return err
	}
	opened, err := os.ReadFile(openedPath)
	if err != nil {
		return err
	}
	fmt.Printf("  recovered  = %d bytes, sha256 %s\n", len(opened), envelope.Sha256Hex(opened))
	fmt.Printf("  digests match = %t\n", envelope.Sha256Hex(opened) == envelope.Sha256Hex(payload))

	// A single flipped byte in the middle of the file is caught.
	tampered := append([]byte{}, sealed...)
	tampered[len(tampered)/2] ^= 0xFF
	if err := reportOpen(scheme, masterKey, dir, "tampered chunk", tampered, aad); err != nil {
		return err
	}

	// So is a stream cut short: the final chunk is flagged as such in its
	// nonce, so a truncated file can never look complete.
	cut := sealed[:len(sealed)-(len(payload)%chunkSize+envelope.TagSize)]
	if err := reportOpen(scheme, masterKey, dir, "truncated stream", cut, aad); err != nil {
		return err
	}

	// The wrong context is rejected as well.
	return reportOpen(scheme, masterKey, dir, "wrong aad", sealed, []byte("other.bin"))
}

// reportOpen writes a mangled stream to a scratch file and prints whether
// opening it fails. Only a broken scratch file is an error worth returning.
func reportOpen(scheme *envelope.Scheme, masterKey []byte, dir, label string, blob, aad []byte) error {
	name := strings.ReplaceAll(label, " ", "-")
	src := filepath.Join(dir, name+".enc")
	if err := os.WriteFile(src, blob, 0o600); err != nil {
		return err
	}

	_, err := scheme.OpenFileAAD(masterKey, filepath.Join(dir, name+".out"), src, aad)
	fmt.Printf("  %-16s fails = %t (%v)\n", label, err != nil, err)
	return nil
}

// paddingDemo shows how padding hides the plaintext length. A sealed stream
// otherwise states its chunk size in the clear, so the exact payload size
// follows from the file size; the padded API rounds the payload up to a Padme
// bucket first, so every length inside one bucket lands on the same size on
// disk.
//
// Everything here runs through SealPaddedStreamAAD, straight from memory to
// memory. Padding needs the payload length up front, not the payload itself:
// the frame is emitted first, the payload is streamed through one chunk at a
// time and the zero padding is generated as the sealer asks for it, so nothing
// is ever staged on disk. SealPaddedFileAAD is the same code with the size
// taken from a Stat.
func paddingDemo(masterKey []byte) error {
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
	})

	section("10. Pad before sealing to hide the plaintext length")

	// Three payloads of different sizes that share one Padme bucket, plus one
	// from the next bucket up.
	sizes := []int{94500, 96037, 96200, 100000}
	fmt.Printf("  %10s %10s %12s %12s %8s\n", "payload", "padded", "sealed+pad", "sealed raw", "overhead")
	for _, n := range sizes {
		payload := make([]byte, n)
		if _, err := rand.Read(payload); err != nil {
			return err
		}

		// A stable identifier for the record doubles as context, as the file
		// name does in the stream demo above.
		aad := []byte(fmt.Sprintf("doc:%d", n))

		// Seal padded, in memory. The size is the only thing the padding
		// needs in advance; src stays an ordinary io.Reader.
		var padded bytes.Buffer
		if _, err := scheme.SealPaddedStreamAAD(masterKey, &padded, bytes.NewReader(payload), int64(n), aad); err != nil {
			return err
		}

		// The same payload without padding, for comparison.
		var raw bytes.Buffer
		if _, err := scheme.SealStreamAAD(masterKey, &raw, bytes.NewReader(payload), aad); err != nil {
			return err
		}

		fmt.Printf("  %10d %10d %12d %12d %7.1f%%\n",
			n, envelope.PaddedSize(int64(n)), padded.Len(), raw.Len(),
			100*float64(padded.Len()-n)/float64(n))

		// Round-trip the padded stream: the padding is authenticated, then
		// dropped, so what comes back is the original payload.
		var opened bytes.Buffer
		got, err := scheme.OpenPaddedStreamAAD(masterKey, &opened, bytes.NewReader(padded.Bytes()), aad)
		if err != nil {
			return err
		}
		if got != int64(n) || envelope.Sha256Hex(opened.Bytes()) != envelope.Sha256Hex(payload) {
			return fmt.Errorf("padded round-trip failed for %d bytes", n)
		}
	}
	fmt.Println("  the first three payloads differ in size but seal to the same number of bytes,")
	fmt.Println("  so the size no longer identifies which one is stored")

	// A stream sealed without padding is not a padded payload, and says so
	// instead of handing back the frame as if it were data.
	var unpadded bytes.Buffer
	if _, err := scheme.SealStream(masterKey, &unpadded, strings.NewReader("no frame here")); err != nil {
		return err
	}
	_, err := scheme.OpenPaddedStream(masterKey, &bytes.Buffer{}, &unpadded)
	fmt.Printf("  open an unpadded stream as padded fails = %t (%v)\n", err != nil, err)

	// The file forms are the same scheme with the size read from a Stat, for
	// payloads that already live on disk:
	//   scheme.SealPaddedFileAAD(masterKey, dstPath, srcPath, aad)
	//   scheme.OpenPaddedFileAAD(masterKey, dstPath, srcPath, aad)
	return nil
}

// deferredPaddingDemo handles browser uploads, where the size is unknown until
// the bytes have all arrived. SealPaddedStream needs it up front, so it cannot
// be used on the request path.
//
// Do it in two stages instead: SealStream the upload as it arrives (no size
// needed), then pad it in a background job once the length is known. Neither
// stage writes plaintext to disk, and a crash leaves a valid sealed object.
//
// Track what still needs padding in your own store: the two forms are
// domain-separated, so an unpadded object fails as ErrStreamAuth instead of
// announcing itself.
func deferredPaddingDemo(masterKey []byte) error {
	const chunkSize = envelope.MinChunkSize
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
		ChunkSize:   chunkSize,
	})

	section("11. Deferred padding: seal an upload now, pad it later")

	payload := make([]byte, 97531)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	aad := []byte("obj:42")

	// Stage 1, the request path. This is exactly what a handler does with
	// multipart.Part: no size, no temp file, one chunk of memory.
	upload := browserUpload(payload)
	var stored bytes.Buffer
	n, err := scheme.SealStreamAAD(masterKey, &stored, upload, aad)
	if err != nil {
		return err
	}
	fmt.Printf("  stage 1 (request)   SealStreamAAD wants no size -> sealed %d bytes\n", n)
	fmt.Printf("                      stored unpadded: %d bytes; content hidden, length not\n", stored.Len())

	// Stage 2, the background job. The length is not stored anywhere: an
	// unpadded stream is StreamHeaderSize + n + 16*ceil(n/chunkSize) bytes, and
	// envelope.PlaintextLen inverts that exactly. The leak padding exists to
	// remove is what tells the padder how much to pad.
	size, ok := envelope.PlaintextLen(int64(stored.Len()), chunkSize)
	fmt.Printf("                      length recovered from the sealed size alone = %d (exact=%t)\n",
		size, ok && size == n)
	if !ok {
		return fmt.Errorf("could not recover the plaintext length")
	}

	r, err := scheme.OpenReaderAAD(masterKey, bytes.NewReader(stored.Bytes()), aad)
	if err != nil {
		return err
	}
	var padded bytes.Buffer
	if _, err := scheme.SealPaddedStreamAAD(masterKey, &padded, r, size, aad); err != nil {
		return err
	}
	fmt.Printf("  stage 2 (padder)    resealed padded: %d bytes (PaddedSize=%d, bucket hides the low bits)\n",
		padded.Len(), envelope.PaddedSize(size))

	// The padded object is what finally replaces the unpadded one, atomically.
	var back bytes.Buffer
	got, err := scheme.OpenPaddedStreamAAD(masterKey, &back, bytes.NewReader(padded.Bytes()), aad)
	if err != nil {
		return err
	}
	fmt.Printf("                      round-trip: %d bytes, digests match = %t\n",
		got, envelope.Sha256Hex(back.Bytes()) == envelope.Sha256Hex(payload))

	// The two states cannot be confused: the padded helpers domain-separate
	// their AAD, so neither reader accepts the other's stream. That costs the
	// diagnosis, since a not-yet-padded object fails as ErrStreamAuth, the same
	// as a wrong key. Retrying with the plain reader is what tells them apart.
	_, err = scheme.OpenPaddedStreamAAD(masterKey, io.Discard, bytes.NewReader(stored.Bytes()), aad)
	fmt.Printf("                      unpadded opened as padded fails = %t (%v)\n",
		errors.Is(err, envelope.ErrStreamAuth), err)
	_, err = scheme.OpenStreamAAD(masterKey, io.Discard, bytes.NewReader(stored.Bytes()), aad)
	fmt.Printf("                      ...and the plain reader identifies it = %t\n", err == nil)
	return nil
}

// browserUpload returns the file part of a plain multipart/form-data POST,
// the way a browser sends it: a filename, and nowhere any byte count.
func browserUpload(payload []byte) *multipart.Part {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", "report.pdf")
	if err == nil {
		_, err = fw.Write(payload)
	}
	if err == nil {
		err = w.Close()
	}
	if err != nil {
		// building an in-memory form cannot realistically fail.
		panic(err)
	}

	_, params, err := mime.ParseMediaType(w.FormDataContentType())
	if err != nil {
		panic(err)
	}
	part, err := multipart.NewReader(&body, params["boundary"]).NextPart()
	if err != nil {
		panic(err)
	}
	return part
}

// dumpStreamHeader prints the cleartext header at the start of a sealed
// stream: version, salt and the parameters needed to rebuild the chunk keys
// and nonces.
func dumpStreamHeader(blob []byte) {
	prefixLen := envelope.NonceSize - 9 // counter(8) + final flag(1)
	if len(blob) < envelope.StreamHeaderSize {
		fmt.Println("  too short to be a sealed stream")
		return
	}

	saltLen := int(blob[1])
	salt := blob[2 : 2+saltLen]
	rest := blob[2+saltLen:]

	fmt.Println("  stream header breakdown:")
	fmt.Printf("    version     = 0x%02x\n", blob[0])
	fmt.Printf("    saltLen     = %d\n", saltLen)
	dumpBytes("  salt", salt)
	fmt.Printf("    chunkSize   = %d\n", binary.BigEndian.Uint32(rest[:4]))
	dumpBytes("  noncePrefix", rest[4:4+prefixLen])
	fmt.Printf("    chunk nonce = noncePrefix || counter(8) || final flag(1)\n")
}
