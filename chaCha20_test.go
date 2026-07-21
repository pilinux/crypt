package crypt

import (
	"bytes"
	"testing"
)

// aead bundles the parallel function set of one AEAD cipher so ChaCha20-Poly1305
// and XChaCha20-Poly1305 can share the same table-driven tests.
type aead struct {
	name      string
	nonceSize int // random nonce length in bytes
	tagSize   int // Poly1305 tag length

	encByte   func(key, input []byte) ([]byte, []byte, error)
	decByte   func(key, nonce, ciphertext []byte) ([]byte, error)
	encByteNA func(key, input []byte) ([]byte, error)
	decByteNA func(key, ciphertext []byte) ([]byte, error)

	encStr   func(key []byte, text string) ([]byte, []byte, error)
	decStr   func(key, nonce, ciphertext []byte) (string, error)
	encStrNA func(key []byte, text string) ([]byte, error)
	decStrNA func(key, ciphertext []byte) (string, error)
}

func aeads() []aead {
	return []aead{
		{
			name: "ChaCha20-Poly1305", nonceSize: 12, tagSize: 16,
			encByte:   EncryptByteChacha20poly1305,
			decByte:   DecryptByteChacha20poly1305,
			encByteNA: EncryptByteChacha20poly1305WithNonceAppended,
			decByteNA: DecryptByteChacha20poly1305WithNonceAppended,
			encStr:    EncryptChacha20poly1305,
			decStr:    DecryptChacha20poly1305,
			encStrNA:  EncryptChacha20poly1305WithNonceAppended,
			decStrNA:  DecryptChacha20poly1305WithNonceAppended,
		},
		{
			name: "XChaCha20-Poly1305", nonceSize: 24, tagSize: 16,
			encByte:   EncryptByteXChacha20poly1305,
			decByte:   DecryptByteXChacha20poly1305,
			encByteNA: EncryptByteXChacha20poly1305WithNonceAppended,
			decByteNA: DecryptByteXChacha20poly1305WithNonceAppended,
			encStr:    EncryptXChacha20poly1305,
			decStr:    DecryptXChacha20poly1305,
			encStrNA:  EncryptXChacha20poly1305WithNonceAppended,
			decStrNA:  DecryptXChacha20poly1305WithNonceAppended,
		},
	}
}

func TestChacha20RoundTrip(t *testing.T) {
	const text = "the quick brown fox jumps over the lazy dog"

	for _, a := range aeads() {
		t.Run(a.name, func(t *testing.T) {
			key := mustBytes(t, 32) // both ciphers require a 256-bit key

			t.Run("string", func(t *testing.T) {
				ciphertext, nonce, err := a.encStr(key, text)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if len(nonce) != a.nonceSize {
					t.Errorf("nonce len = %d, want %d", len(nonce), a.nonceSize)
				}
				got, err := a.decStr(key, nonce, ciphertext)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if got != text {
					t.Errorf("round-trip mismatch: got %q, want %q", got, text)
				}
			})

			t.Run("bytes", func(t *testing.T) {
				in := []byte(text)
				ciphertext, nonce, err := a.encByte(key, in)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if bytes.Contains(ciphertext, in) {
					t.Error("plaintext appears in ciphertext")
				}
				got, err := a.decByte(key, nonce, ciphertext)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if !bytes.Equal(got, in) {
					t.Errorf("round-trip mismatch: got %q, want %q", got, in)
				}
			})
		})
	}
}

func TestChacha20WithNonceAppended(t *testing.T) {
	const text = "attack at dawn"

	for _, a := range aeads() {
		t.Run(a.name, func(t *testing.T) {
			key := mustBytes(t, 32)

			t.Run("string", func(t *testing.T) {
				ciphertext, err := a.encStrNA(key, text)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if want := a.nonceSize + len(text) + a.tagSize; len(ciphertext) != want {
					t.Errorf("ciphertext len = %d, want %d (nonce+plaintext+tag)", len(ciphertext), want)
				}
				got, err := a.decStrNA(key, ciphertext)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if got != text {
					t.Errorf("round-trip mismatch: got %q, want %q", got, text)
				}
			})

			t.Run("bytes", func(t *testing.T) {
				in := []byte(text)
				ciphertext, err := a.encByteNA(key, in)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				got, err := a.decByteNA(key, ciphertext)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if !bytes.Equal(got, in) {
					t.Errorf("round-trip mismatch: got %q, want %q", got, in)
				}
			})
		})
	}
}

func TestChacha20Errors(t *testing.T) {
	for _, a := range aeads() {
		t.Run(a.name, func(t *testing.T) {
			key := mustBytes(t, 32)

			t.Run("invalidKeySize", func(t *testing.T) {
				if _, _, err := a.encByte([]byte("too-short"), []byte("x")); err == nil {
					t.Error("expected error for invalid key size, got nil")
				}
			})

			t.Run("wrongKey", func(t *testing.T) {
				ciphertext, err := a.encByteNA(key, []byte("secret"))
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if _, err := a.decByteNA(mustBytes(t, 32), ciphertext); err == nil {
					t.Error("decryption with wrong key succeeded, want failure")
				}
			})

			t.Run("tampered", func(t *testing.T) {
				ciphertext, err := a.encByteNA(key, []byte("secret"))
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				ciphertext[len(ciphertext)-1] ^= 0xFF
				if _, err := a.decByteNA(key, ciphertext); err == nil {
					t.Error("decryption of tampered ciphertext succeeded, want failure")
				}
			})

			t.Run("nonceAppendedTooShort", func(t *testing.T) {
				if _, err := a.decByteNA(key, []byte{1, 2, 3}); err == nil {
					t.Error("expected error for too-short ciphertext, got nil")
				}
			})
		})
	}
}

func TestChacha20UniqueCiphertexts(t *testing.T) {
	for _, a := range aeads() {
		t.Run(a.name, func(t *testing.T) {
			key := mustBytes(t, 32)
			x, _ := a.encStrNA(key, "same")
			y, _ := a.encStrNA(key, "same")
			if bytes.Equal(x, y) {
				t.Error("two encryptions of the same plaintext are identical (nonce not random?)")
			}
		})
	}
}
