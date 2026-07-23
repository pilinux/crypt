package crypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// testRSAKeyPair generates a fresh 2048-bit RSA key pair and returns it as
// PEM-encoded strings in the exact formats NewEncoder/NewDecoder expect:
// a PKIX "PUBLIC KEY" and a PKCS#8 "PRIVATE KEY". It is shared with the
// encoder/decoder tests in this package.
func testRSAKeyPair(t *testing.T) (pubPEM, privPEM string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	return pubPEM, privPEM
}

func TestRSARoundTrip(t *testing.T) {
	pubPEM, privPEM := testRSAKeyPair(t)
	const text = "Hello world"

	t.Run("stringDefaultSHA256", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		if enc.Err != nil {
			t.Fatalf("NewEncoder: %v", enc.Err)
		}
		dec := NewDecoder(privPEM)
		if dec.Err != nil {
			t.Fatalf("NewDecoder: %v", dec.Err)
		}

		ciphertext, err := enc.EncryptRSA(text)
		if err != nil {
			t.Fatalf("EncryptRSA: %v", err)
		}
		got, err := dec.DecryptRSA(ciphertext)
		if err != nil {
			t.Fatalf("DecryptRSA: %v", err)
		}
		if got != text {
			t.Errorf("round-trip mismatch: got %q, want %q", got, text)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		dec := NewDecoder(privPEM)
		in := []byte(text)

		ciphertext, err := enc.EncryptByteRSA(in)
		if err != nil {
			t.Fatalf("EncryptByteRSA: %v", err)
		}
		if bytes.Contains(ciphertext, in) {
			t.Error("plaintext appears in ciphertext")
		}
		got, err := dec.DecryptByteRSA(ciphertext)
		if err != nil {
			t.Fatalf("DecryptByteRSA: %v", err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("round-trip mismatch: got %q, want %q", got, in)
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		enc.HashAlg = SHA512
		dec := NewDecoder(privPEM)
		dec.HashAlg = SHA512

		ciphertext, err := enc.EncryptRSA(text)
		if err != nil {
			t.Fatalf("EncryptRSA: %v", err)
		}
		got, err := dec.DecryptRSA(ciphertext)
		if err != nil {
			t.Fatalf("DecryptRSA: %v", err)
		}
		if got != text {
			t.Errorf("round-trip mismatch: got %q, want %q", got, text)
		}
	})

	t.Run("emptyPlaintext", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		dec := NewDecoder(privPEM)

		ciphertext, err := enc.EncryptRSA("")
		if err != nil {
			t.Fatalf("EncryptRSA: %v", err)
		}
		got, err := dec.DecryptRSA(ciphertext)
		if err != nil {
			t.Fatalf("DecryptRSA: %v", err)
		}
		if got != "" {
			t.Errorf("expected empty plaintext, got %q", got)
		}
	})
}

func TestRSAErrors(t *testing.T) {
	pubPEM, privPEM := testRSAKeyPair(t)

	t.Run("hashMismatch", func(t *testing.T) {
		enc := NewEncoder(pubPEM) // encrypt with default SHA-256
		dec := NewDecoder(privPEM)
		dec.HashAlg = SHA512 // decrypt expecting SHA-512

		ciphertext, err := enc.EncryptRSA("Hello world")
		if err != nil {
			t.Fatalf("EncryptRSA: %v", err)
		}
		if _, err := dec.DecryptRSA(ciphertext); err == nil {
			t.Error("decrypt with mismatched hash succeeded, want failure")
		}
	})

	t.Run("unsupportedHash", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		enc.HashAlg = HashAlgorithm(99) // not SHA256/SHA512
		if _, err := enc.EncryptRSA("Hello world"); err == nil {
			t.Error("encrypt with unsupported hash succeeded, want failure")
		}

		dec := NewDecoder(privPEM)
		dec.HashAlg = HashAlgorithm(99)
		if _, err := dec.DecryptRSA([]byte("whatever")); err == nil {
			t.Error("decrypt with unsupported hash succeeded, want failure")
		}
	})

	t.Run("wrongKey", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		_, otherPriv := testRSAKeyPair(t)
		dec := NewDecoder(otherPriv)

		ciphertext, err := enc.EncryptRSA("Hello world")
		if err != nil {
			t.Fatalf("EncryptRSA: %v", err)
		}
		if _, err := dec.DecryptRSA(ciphertext); err == nil {
			t.Error("decrypt with wrong private key succeeded, want failure")
		}
	})

	t.Run("plaintextTooLong", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		// RSA-OAEP with a 2048-bit key and SHA-256 caps the message at 190
		// bytes; anything larger must fail rather than truncate.
		if _, err := enc.EncryptByteRSA(bytes.Repeat([]byte{'a'}, 256)); err == nil {
			t.Error("encrypt of oversized plaintext succeeded, want failure")
		}
	})
}

// TestRSANonRSAKey verifies that a syntactically valid but non-RSA PEM key is
// rejected by the type assertion rather than misused.
func TestRSANonRSAKey(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	t.Run("encrypt", func(t *testing.T) {
		enc := NewEncoder(pubPEM)
		if enc.Err != nil {
			t.Fatalf("NewEncoder unexpectedly failed on a PUBLIC KEY block: %v", enc.Err)
		}
		if _, err := enc.EncryptRSA("x"); err == nil {
			t.Error("EncryptRSA with an Ed25519 key succeeded, want failure")
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		dec := NewDecoder(privPEM)
		if dec.Err != nil {
			t.Fatalf("NewDecoder unexpectedly failed on a PRIVATE KEY block: %v", dec.Err)
		}
		if _, err := dec.DecryptRSA([]byte("whatever")); err == nil {
			t.Error("DecryptRSA with an Ed25519 key succeeded, want failure")
		}
	})
}

// TestRSAMalformedKeyBytes verifies that a PEM block of the right type but with
// undecodable DER bytes surfaces a parse error instead of panicking.
func TestRSAMalformedKeyBytes(t *testing.T) {
	t.Run("encrypt", func(t *testing.T) {
		enc := &Encoder{PubKeyBlock: &pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}}
		if _, err := enc.EncryptRSA("x"); err == nil {
			t.Error("EncryptRSA with malformed key bytes succeeded, want failure")
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		dec := &Decoder{PriKeyBlock: &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}}
		if _, err := dec.DecryptRSA([]byte("x")); err == nil {
			t.Error("DecryptRSA with malformed key bytes succeeded, want failure")
		}
	})
}
