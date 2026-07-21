package crypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// mustBytes returns n cryptographically random bytes, failing the test on
// error. It is shared by the other _test.go files in this package.
func mustBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read(%d): %v", n, err)
	}
	return b
}

// aesKeySizes maps a human name to the key length that selects each AES variant.
var aesKeySizes = map[string]int{"AES-128": 16, "AES-192": 24, "AES-256": 32}

func TestAesGcmRoundTrip(t *testing.T) {
	const text = "the quick brown fox jumps over the lazy dog"

	for name, size := range aesKeySizes {
		t.Run(name, func(t *testing.T) {
			key := mustBytes(t, size)

			t.Run("string", func(t *testing.T) {
				ciphertext, nonce, err := EncryptAesGcm(key, text)
				if err != nil {
					t.Fatalf("EncryptAesGcm: %v", err)
				}
				got, err := DecryptAesGcm(key, nonce, ciphertext)
				if err != nil {
					t.Fatalf("DecryptAesGcm: %v", err)
				}
				if got != text {
					t.Errorf("round-trip mismatch: got %q, want %q", got, text)
				}
			})

			t.Run("bytes", func(t *testing.T) {
				in := []byte(text)
				ciphertext, nonce, err := EncryptByteAesGcm(key, in)
				if err != nil {
					t.Fatalf("EncryptByteAesGcm: %v", err)
				}
				if bytes.Contains(ciphertext, in) {
					t.Error("plaintext appears in ciphertext")
				}
				got, err := DecryptByteAesGcm(key, nonce, ciphertext)
				if err != nil {
					t.Fatalf("DecryptByteAesGcm: %v", err)
				}
				if !bytes.Equal(got, in) {
					t.Errorf("round-trip mismatch: got %q, want %q", got, in)
				}
			})
		})
	}
}

func TestAesGcmWithNonceAppended(t *testing.T) {
	const text = "attack at dawn"
	const nonceSize = 12 // AES-GCM standard nonce
	const tagSize = 16   // GCM authentication tag

	for name, size := range aesKeySizes {
		t.Run(name, func(t *testing.T) {
			key := mustBytes(t, size)

			t.Run("string", func(t *testing.T) {
				ciphertext, err := EncryptAesGcmWithNonceAppended(key, text)
				if err != nil {
					t.Fatalf("EncryptAesGcmWithNonceAppended: %v", err)
				}
				if want := nonceSize + len(text) + tagSize; len(ciphertext) != want {
					t.Errorf("ciphertext len = %d, want %d (nonce+plaintext+tag)", len(ciphertext), want)
				}
				got, err := DecryptAesGcmWithNonceAppended(key, ciphertext)
				if err != nil {
					t.Fatalf("DecryptAesGcmWithNonceAppended: %v", err)
				}
				if got != text {
					t.Errorf("round-trip mismatch: got %q, want %q", got, text)
				}
			})

			t.Run("bytes", func(t *testing.T) {
				in := []byte(text)
				ciphertext, err := EncryptByteAesGcmWithNonceAppended(key, in)
				if err != nil {
					t.Fatalf("EncryptByteAesGcmWithNonceAppended: %v", err)
				}
				got, err := DecryptByteAesGcmWithNonceAppended(key, ciphertext)
				if err != nil {
					t.Fatalf("DecryptByteAesGcmWithNonceAppended: %v", err)
				}
				if !bytes.Equal(got, in) {
					t.Errorf("round-trip mismatch: got %q, want %q", got, in)
				}
			})
		})
	}
}

func TestAesGcmEmptyPlaintext(t *testing.T) {
	key := mustBytes(t, 32)
	ciphertext, err := EncryptByteAesGcmWithNonceAppended(key, []byte{})
	if err != nil {
		t.Fatalf("EncryptByteAesGcmWithNonceAppended: %v", err)
	}
	got, err := DecryptByteAesGcmWithNonceAppended(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptByteAesGcmWithNonceAppended: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestAesGcmUniqueCiphertexts(t *testing.T) {
	key := mustBytes(t, 32)
	a, _ := EncryptAesGcmWithNonceAppended(key, "same")
	b, _ := EncryptAesGcmWithNonceAppended(key, "same")
	if bytes.Equal(a, b) {
		t.Error("two encryptions of the same plaintext are identical (nonce not random?)")
	}
}

func TestAesGcmErrors(t *testing.T) {
	key := mustBytes(t, 32)

	t.Run("encryptInvalidKeySize", func(t *testing.T) {
		if _, _, err := EncryptAesGcm([]byte("too-short"), "x"); err == nil {
			t.Error("expected error for invalid key size, got nil")
		}
	})

	t.Run("decryptInvalidKeySize", func(t *testing.T) {
		if _, err := DecryptAesGcm([]byte("too-short"), mustBytes(t, 12), []byte("x")); err == nil {
			t.Error("expected error for invalid key size, got nil")
		}
	})

	t.Run("wrongKey", func(t *testing.T) {
		ciphertext, err := EncryptAesGcmWithNonceAppended(key, "secret")
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if _, err := DecryptAesGcmWithNonceAppended(mustBytes(t, 32), ciphertext); err == nil {
			t.Error("decryption with wrong key succeeded, want failure")
		}
	})

	t.Run("tampered", func(t *testing.T) {
		ciphertext, err := EncryptAesGcmWithNonceAppended(key, "secret")
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		ciphertext[len(ciphertext)-1] ^= 0xFF
		if _, err := DecryptAesGcmWithNonceAppended(key, ciphertext); err == nil {
			t.Error("decryption of tampered ciphertext succeeded, want failure")
		}
	})

	t.Run("nonceAppendedTooShort", func(t *testing.T) {
		if _, err := DecryptByteAesGcmWithNonceAppended(key, []byte{1, 2, 3}); err == nil {
			t.Error("expected error for too-short ciphertext, got nil")
		}
	})
}
