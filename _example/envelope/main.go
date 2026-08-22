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
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pilinux/crypt"
	"github.com/pilinux/crypt/envelope"
)

func main() {
	// The application secret, typically read from an env var such as
	// ENCRYPTION_SECRET. It must be at least envelope.MinSecretLength chars of
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

	// 11. Fingerprint a payload and mint a random file ID.
	section("11. Helpers")
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
// follows from the file size; SealPaddedFile rounds the payload up to a Padme
// bucket first, so every length inside one bucket lands on the same size on
// disk.
func paddingDemo(masterKey []byte) error {
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
	})

	dir, err := os.MkdirTemp("", "crypt-envelope-padding-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	section("10. Pad before sealing to hide the plaintext length")

	// Three payloads of different sizes that share one Padme bucket, plus one
	// from the next bucket up.
	sizes := []int{94500, 96037, 96200, 100000}
	fmt.Printf("  %10s %10s %12s %12s %8s\n", "payload", "padded", "sealed+pad", "sealed raw", "overhead")
	for i, n := range sizes {
		payload := make([]byte, n)
		if _, err := rand.Read(payload); err != nil {
			return err
		}
		src := filepath.Join(dir, fmt.Sprintf("f%d.bin", i))
		if err := os.WriteFile(src, payload, 0o600); err != nil {
			return err
		}

		// The file name doubles as context, as in the stream demo above.
		aad := []byte(filepath.Base(src))
		padded := filepath.Join(dir, fmt.Sprintf("f%d.pad.enc", i))
		if _, err := scheme.SealPaddedFileAAD(masterKey, padded, src, aad); err != nil {
			return err
		}
		plain := filepath.Join(dir, fmt.Sprintf("f%d.enc", i))
		if _, err := scheme.SealFileAAD(masterKey, plain, src, aad); err != nil {
			return err
		}

		padSize, err := fileSize(padded)
		if err != nil {
			return err
		}
		rawSize, err := fileSize(plain)
		if err != nil {
			return err
		}
		fmt.Printf("  %10d %10d %12d %12d %7.1f%%\n",
			n, envelope.PaddedSize(int64(n)), padSize, rawSize,
			100*float64(padSize-int64(n))/float64(n))

		// Round-trip the padded file: the padding is authenticated, then
		// dropped, so what comes back is the original payload.
		opened := filepath.Join(dir, fmt.Sprintf("f%d.out", i))
		got, err := scheme.OpenPaddedFileAAD(masterKey, opened, padded, aad)
		if err != nil {
			return err
		}
		back, err := os.ReadFile(opened)
		if err != nil {
			return err
		}
		if got != int64(n) || envelope.Sha256Hex(back) != envelope.Sha256Hex(payload) {
			return fmt.Errorf("padded round-trip failed for %d bytes", n)
		}
	}
	fmt.Println("  the first three payloads differ in size but seal to the same number of bytes,")
	fmt.Println("  so the file size no longer identifies which one is on disk")

	// A stream sealed without padding is not a padded payload, and says so
	// instead of handing back the frame as if it were data.
	src := filepath.Join(dir, "unpadded.bin")
	if err := os.WriteFile(src, []byte("no frame here"), 0o600); err != nil {
		return err
	}
	sealed := filepath.Join(dir, "unpadded.enc")
	if _, err := scheme.SealFile(masterKey, sealed, src); err != nil {
		return err
	}
	_, err = scheme.OpenPaddedFile(masterKey, filepath.Join(dir, "unpadded.out"), sealed)
	fmt.Printf("  open an unpadded stream as padded fails = %t (%v)\n", err != nil, err)
	return nil
}

// fileSize returns the size of path in bytes.
func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// dumpStreamHeader prints the cleartext header at the start of a sealed
// stream: version, salt and the parameters needed to rebuild the chunk keys
// and nonces.
func dumpStreamHeader(blob []byte) {
	prefixLen := envelope.NonceSize - 9 // counter(8) + final flag(1)
	if len(blob) < 2+envelope.SaltSize+4+prefixLen {
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
