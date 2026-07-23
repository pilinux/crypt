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

	encByteNAAAD func(key, input, additionalData []byte) ([]byte, error)
	decByteNAAAD func(key, ciphertext, additionalData []byte) ([]byte, error)

	encStr   func(key []byte, text string) ([]byte, []byte, error)
	decStr   func(key, nonce, ciphertext []byte) (string, error)
	encStrNA func(key []byte, text string) ([]byte, error)
	decStrNA func(key, ciphertext []byte) (string, error)
}

func aeads() []aead {
	return []aead{
		{
			name: "ChaCha20-Poly1305", nonceSize: 12, tagSize: 16,
			encByte:      EncryptByteChacha20poly1305,
			decByte:      DecryptByteChacha20poly1305,
			encByteNA:    EncryptByteChacha20poly1305WithNonceAppended,
			decByteNA:    DecryptByteChacha20poly1305WithNonceAppended,
			encByteNAAAD: EncryptByteChacha20poly1305WithNonceAppendedAAD,
			decByteNAAAD: DecryptByteChacha20poly1305WithNonceAppendedAAD,
			encStr:       EncryptChacha20poly1305,
			decStr:       DecryptChacha20poly1305,
			encStrNA:     EncryptChacha20poly1305WithNonceAppended,
			decStrNA:     DecryptChacha20poly1305WithNonceAppended,
		},
		{
			name: "XChaCha20-Poly1305", nonceSize: 24, tagSize: 16,
			encByte:      EncryptByteXChacha20poly1305,
			decByte:      DecryptByteXChacha20poly1305,
			encByteNA:    EncryptByteXChacha20poly1305WithNonceAppended,
			decByteNA:    DecryptByteXChacha20poly1305WithNonceAppended,
			encByteNAAAD: EncryptByteXChacha20poly1305WithNonceAppendedAAD,
			decByteNAAAD: DecryptByteXChacha20poly1305WithNonceAppendedAAD,
			encStr:       EncryptXChacha20poly1305,
			decStr:       DecryptXChacha20poly1305,
			encStrNA:     EncryptXChacha20poly1305WithNonceAppended,
			decStrNA:     DecryptXChacha20poly1305WithNonceAppended,
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

func TestChacha20WithNonceAppendedAAD(t *testing.T) {
	const text = "attack at dawn"
	aad := []byte("record:42")

	for _, a := range aeads() {
		t.Run(a.name, func(t *testing.T) {
			key := mustBytes(t, 32)

			t.Run("roundTrip", func(t *testing.T) {
				in := []byte(text)
				ciphertext, err := a.encByteNAAAD(key, in, aad)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if want := a.nonceSize + len(text) + a.tagSize; len(ciphertext) != want {
					t.Errorf("ciphertext len = %d, want %d (AAD must not be stored)", len(ciphertext), want)
				}
				got, err := a.decByteNAAAD(key, ciphertext, aad)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if !bytes.Equal(got, in) {
					t.Errorf("round-trip mismatch: got %q, want %q", got, in)
				}
			})

			t.Run("wrongAADFails", func(t *testing.T) {
				ciphertext, err := a.encByteNAAAD(key, []byte(text), aad)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if _, err := a.decByteNAAAD(key, ciphertext, []byte("record:7")); err == nil {
					t.Error("decryption with wrong AAD succeeded, want failure")
				}
				if _, err := a.decByteNA(key, ciphertext); err == nil {
					t.Error("decryption without AAD succeeded, want failure")
				}
			})

			t.Run("nilAADMatchesPlainVariant", func(t *testing.T) {
				ciphertext, err := a.encByteNAAAD(key, []byte(text), nil)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if _, err := a.decByteNA(key, ciphertext); err != nil {
					t.Errorf("plain decrypt of nil-AAD ciphertext failed: %v", err)
				}

				ciphertext, err = a.encByteNA(key, []byte(text))
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				if _, err := a.decByteNAAAD(key, ciphertext, nil); err != nil {
					t.Errorf("nil-AAD decrypt of plain ciphertext failed: %v", err)
				}
			})

			t.Run("tooShort", func(t *testing.T) {
				if _, err := a.decByteNAAAD(key, []byte{1, 2, 3}, aad); err == nil {
					t.Error("expected error for too-short ciphertext, got nil")
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

			t.Run("wrongNonceLength", func(t *testing.T) {
				// a wrong-length nonce must return an error, not panic:
				// the test binary would crash on an unrecovered panic.
				ciphertext, nonce, err := a.encByte(key, []byte("secret"))
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				for _, badLen := range []int{0, a.nonceSize - 1, a.nonceSize + 1} {
					if _, err := a.decByte(key, make([]byte, badLen), ciphertext); err == nil {
						t.Errorf("decrypt with %d-byte nonce succeeded, want error", badLen)
					}
				}
				// the correct length still round-trips
				if _, err := a.decByte(key, nonce, ciphertext); err != nil {
					t.Errorf("decrypt with correct nonce failed: %v", err)
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
