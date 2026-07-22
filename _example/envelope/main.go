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
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

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

	// 9. Fingerprint a payload and mint a random file ID.
	section("9. Helpers")
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
