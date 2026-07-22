package envelope

import (
	"bytes"
	"testing"
)

// newMasterKey is a small helper returning a fresh master key for tests.
func newMasterKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey error: %v", err)
	}
	return key
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt error: %v", err)
	}
	if len(salt) != SaltSize {
		t.Errorf("salt len = %d, want %d", len(salt), SaltSize)
	}

	other, _ := GenerateSalt()
	if bytes.Equal(salt, other) {
		t.Error("two generated salts are identical")
	}
}

func TestDeriveSubKey(t *testing.T) {
	s := Default()
	masterKey := newMasterKey(t)
	salt, _ := GenerateSalt()

	t.Run("lengthAndDeterminism", func(t *testing.T) {
		a, err := s.DeriveSubKey(masterKey, salt)
		if err != nil {
			t.Fatalf("DeriveSubKey error: %v", err)
		}
		if len(a) != KeySize {
			t.Errorf("sub-key len = %d, want %d", len(a), KeySize)
		}

		b, _ := s.DeriveSubKey(masterKey, salt)
		if !bytes.Equal(a, b) {
			t.Error("same master key + salt produced different sub-keys")
		}
	})

	t.Run("differentSaltDifferentKey", func(t *testing.T) {
		otherSalt, _ := GenerateSalt()
		a, _ := s.DeriveSubKey(masterKey, salt)
		b, _ := s.DeriveSubKey(masterKey, otherSalt)
		if bytes.Equal(a, b) {
			t.Error("different salts produced the same sub-key")
		}
	})

	t.Run("differentMasterDifferentKey", func(t *testing.T) {
		a, _ := s.DeriveSubKey(masterKey, salt)
		b, _ := s.DeriveSubKey(newMasterKey(t), salt)
		if bytes.Equal(a, b) {
			t.Error("different master keys produced the same sub-key")
		}
	})

	t.Run("invalidSizes", func(t *testing.T) {
		if _, err := s.DeriveSubKey([]byte("short"), salt); err != ErrInvalidKeySize {
			t.Errorf("err = %v, want ErrInvalidKeySize", err)
		}
		if _, err := s.DeriveSubKey(masterKey, []byte("short")); err != ErrInvalidSaltSize {
			t.Errorf("err = %v, want ErrInvalidSaltSize", err)
		}
	})
}

func TestSealOpenBytes(t *testing.T) {
	s := Default()
	masterKey := newMasterKey(t)

	t.Run("roundTrip", func(t *testing.T) {
		plaintext := []byte("attack at dawn")
		blob, err := s.SealBytes(masterKey, plaintext)
		if err != nil {
			t.Fatalf("SealBytes error: %v", err)
		}
		if bytes.Contains(blob, plaintext) {
			t.Error("plaintext appears in ciphertext envelope")
		}

		got, err := s.OpenBytes(masterKey, blob)
		if err != nil {
			t.Fatalf("OpenBytes error: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
		}
	})

	t.Run("emptyPlaintext", func(t *testing.T) {
		blob, err := s.SealBytes(masterKey, []byte{})
		if err != nil {
			t.Fatalf("SealBytes error: %v", err)
		}
		got, err := s.OpenBytes(masterKey, blob)
		if err != nil {
			t.Fatalf("OpenBytes error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty plaintext, got %d bytes", len(got))
		}
	})

	t.Run("uniqueCiphertexts", func(t *testing.T) {
		// same plaintext must produce different envelopes (random salt + nonce)
		a, _ := s.SealBytes(masterKey, []byte("same"))
		b, _ := s.SealBytes(masterKey, []byte("same"))
		if bytes.Equal(a, b) {
			t.Error("two seals of the same plaintext are identical")
		}
	})

	t.Run("wrongKeyFails", func(t *testing.T) {
		blob, _ := s.SealBytes(masterKey, []byte("secret"))
		if _, err := s.OpenBytes(newMasterKey(t), blob); err == nil {
			t.Error("OpenBytes with wrong master key succeeded, want failure")
		}
	})

	t.Run("tamperFails", func(t *testing.T) {
		blob, _ := s.SealBytes(masterKey, []byte("secret"))
		blob[len(blob)-1] ^= 0xFF
		if _, err := s.OpenBytes(masterKey, blob); err == nil {
			t.Error("OpenBytes of tampered envelope succeeded, want failure")
		}
	})

	t.Run("tamperHeaderFails", func(t *testing.T) {
		// flipping the saltLen byte (1) or a salt byte (2) must fail: the
		// header is authenticated as AAD (and the salt drives the sub-key).
		for _, idx := range []int{1, 2} {
			blob, _ := s.SealBytes(masterKey, []byte("secret"))
			blob[idx] ^= 0x01
			if _, err := s.OpenBytes(masterKey, blob); err == nil {
				t.Errorf("OpenBytes after flipping header byte %d succeeded, want failure", idx)
			}
		}
	})

	t.Run("tamperVersionFails", func(t *testing.T) {
		blob, _ := s.SealBytes(masterKey, []byte("secret"))
		blob[0] ^= 0xFF
		if _, err := s.OpenBytes(masterKey, blob); err != ErrBadEnvelope {
			t.Errorf("err = %v, want ErrBadEnvelope", err)
		}
	})
}

func TestSealOpenBytesAAD(t *testing.T) {
	s := Default()
	masterKey := newMasterKey(t)
	plaintext := []byte("bound to user 42")
	aad := []byte("user:42:ssn")

	t.Run("roundTrip", func(t *testing.T) {
		blob, err := s.SealBytesAAD(masterKey, plaintext, aad)
		if err != nil {
			t.Fatalf("SealBytesAAD error: %v", err)
		}
		got, err := s.OpenBytesAAD(masterKey, blob, aad)
		if err != nil {
			t.Fatalf("OpenBytesAAD error: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
		}
	})

	t.Run("wrongAADFails", func(t *testing.T) {
		blob, _ := s.SealBytesAAD(masterKey, plaintext, aad)
		if _, err := s.OpenBytesAAD(masterKey, blob, []byte("user:7:ssn")); err == nil {
			t.Error("OpenBytesAAD with wrong AAD succeeded, want failure")
		}
	})

	t.Run("missingAADFails", func(t *testing.T) {
		blob, _ := s.SealBytesAAD(masterKey, plaintext, aad)
		if _, err := s.OpenBytes(masterKey, blob); err == nil {
			t.Error("OpenBytes of AAD-bound envelope succeeded, want failure")
		}
	})

	t.Run("unexpectedAADFails", func(t *testing.T) {
		blob, _ := s.SealBytes(masterKey, plaintext)
		if _, err := s.OpenBytesAAD(masterKey, blob, aad); err == nil {
			t.Error("OpenBytesAAD of AAD-less envelope succeeded, want failure")
		}
	})
}

func TestSealOpenString(t *testing.T) {
	s := Default()
	masterKey := newMasterKey(t)

	t.Run("roundTrip", func(t *testing.T) {
		plaintext := "hello, 世界"
		token, err := s.SealString(masterKey, plaintext)
		if err != nil {
			t.Fatalf("SealString error: %v", err)
		}

		got, err := s.OpenString(masterKey, token)
		if err != nil {
			t.Fatalf("OpenString error: %v", err)
		}
		if got != plaintext {
			t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
		}
	})

	t.Run("badBase64", func(t *testing.T) {
		if _, err := s.OpenString(masterKey, "not valid base64!!!"); err != ErrBadEnvelope {
			t.Errorf("err = %v, want ErrBadEnvelope", err)
		}
	})

	t.Run("aadRoundTripAndMismatch", func(t *testing.T) {
		aad := []byte("user:42:email")
		token, err := s.SealStringAAD(masterKey, "alice@example.com", aad)
		if err != nil {
			t.Fatalf("SealStringAAD error: %v", err)
		}
		got, err := s.OpenStringAAD(masterKey, token, aad)
		if err != nil {
			t.Fatalf("OpenStringAAD error: %v", err)
		}
		if got != "alice@example.com" {
			t.Errorf("round-trip mismatch: got %q", got)
		}
		if _, err := s.OpenStringAAD(masterKey, token, []byte("user:7:email")); err == nil {
			t.Error("OpenStringAAD with wrong AAD succeeded, want failure")
		}
	})
}

func TestSealOpenInt64(t *testing.T) {
	s := Default()
	masterKey := newMasterKey(t)

	tests := []int64{0, 1, -1, 42, -9223372036854775808, 9223372036854775807}
	for _, n := range tests {
		token, err := s.SealInt64(masterKey, n)
		if err != nil {
			t.Fatalf("SealInt64(%d) error: %v", n, err)
		}
		got, err := s.OpenInt64(masterKey, token)
		if err != nil {
			t.Fatalf("OpenInt64 error: %v", err)
		}
		if got != n {
			t.Errorf("round-trip mismatch: got %d, want %d", got, n)
		}
	}

	t.Run("badTokenFails", func(t *testing.T) {
		if _, err := s.OpenInt64(masterKey, "garbage"); err == nil {
			t.Error("OpenInt64 of bad token succeeded, want failure")
		}
	})

	t.Run("nonIntegerPlaintext", func(t *testing.T) {
		// a string-sealed token opened as int64 must fail with the generic
		// error; anything but the fixed 8-byte encoding is rejected.
		token, err := s.SealString(masterKey, "not a number")
		if err != nil {
			t.Fatalf("SealString error: %v", err)
		}
		if _, err := s.OpenInt64(masterKey, token); err != ErrNotAnInteger {
			t.Errorf("err = %v, want ErrNotAnInteger", err)
		}
	})

	t.Run("uniformTokenLength", func(t *testing.T) {
		// the fixed-width encoding must hide the magnitude of the value:
		// every int64 token has exactly the same length.
		want := -1
		for _, n := range []int64{0, 7, -1, 9223372036854775807, -9223372036854775808} {
			token, err := s.SealInt64(masterKey, n)
			if err != nil {
				t.Fatalf("SealInt64(%d) error: %v", n, err)
			}
			if want == -1 {
				want = len(token)
			} else if len(token) != want {
				t.Errorf("token for %d has len %d, want %d", n, len(token), want)
			}
		}
	})

	t.Run("aadRoundTripAndMismatch", func(t *testing.T) {
		aad := []byte("user:42:age")
		token, err := s.SealInt64AAD(masterKey, -37, aad)
		if err != nil {
			t.Fatalf("SealInt64AAD error: %v", err)
		}
		got, err := s.OpenInt64AAD(masterKey, token, aad)
		if err != nil {
			t.Fatalf("OpenInt64AAD error: %v", err)
		}
		if got != -37 {
			t.Errorf("round-trip mismatch: got %d, want -37", got)
		}
		if _, err := s.OpenInt64AAD(masterKey, token, []byte("user:7:age")); err == nil {
			t.Error("OpenInt64AAD with wrong AAD succeeded, want failure")
		}
	})
}
