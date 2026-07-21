package envelope

import (
	"bytes"
	"strings"
	"testing"
)

// validSecret is a 40-character secret, comfortably above MinSecretLength.
const validSecret = "0123456789abcdef0123456789abcdef01234567"

func TestDeriveKEK(t *testing.T) {
	s := Default()

	t.Run("tooShort", func(t *testing.T) {
		if _, err := s.DeriveKEK("short"); err != ErrSecretTooShort {
			t.Errorf("err = %v, want ErrSecretTooShort", err)
		}
	})

	t.Run("validLength", func(t *testing.T) {
		kek, err := s.DeriveKEK(validSecret)
		if err != nil {
			t.Fatalf("DeriveKEK error: %v", err)
		}
		if len(kek) != KeySize {
			t.Errorf("KEK len = %d, want %d", len(kek), KeySize)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		a, _ := s.DeriveKEK(validSecret)
		b, _ := s.DeriveKEK(validSecret)
		if !bytes.Equal(a, b) {
			t.Error("same secret produced different KEKs")
		}
	})

	t.Run("differentSecretDifferentKEK", func(t *testing.T) {
		a, _ := s.DeriveKEK(validSecret)
		b, _ := s.DeriveKEK(validSecret + "x")
		if bytes.Equal(a, b) {
			t.Error("different secrets produced the same KEK")
		}
	})

	t.Run("exactMinLength", func(t *testing.T) {
		secret := strings.Repeat("a", MinSecretLength)
		if _, err := s.DeriveKEK(secret); err != nil {
			t.Errorf("DeriveKEK at min length error: %v", err)
		}
	})
}

func TestGenerateMasterKey(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey error: %v", err)
	}
	if len(key) != KeySize {
		t.Errorf("master key len = %d, want %d", len(key), KeySize)
	}

	other, _ := GenerateMasterKey()
	if bytes.Equal(key, other) {
		t.Error("two generated master keys are identical")
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	s := Default()
	kek, _ := s.DeriveKEK(validSecret)
	masterKey, _ := GenerateMasterKey()

	t.Run("roundTrip", func(t *testing.T) {
		wrapped, err := WrapKey(kek, masterKey)
		if err != nil {
			t.Fatalf("WrapKey error: %v", err)
		}
		if bytes.Equal(wrapped, masterKey) {
			t.Error("wrapped key equals plaintext master key")
		}

		got, err := UnwrapKey(kek, wrapped)
		if err != nil {
			t.Fatalf("UnwrapKey error: %v", err)
		}
		if !bytes.Equal(got, masterKey) {
			t.Error("unwrapped key does not match original master key")
		}
	})

	t.Run("wrongKEKFails", func(t *testing.T) {
		wrapped, _ := WrapKey(kek, masterKey)
		otherKEK, _ := s.DeriveKEK(validSecret + "different")
		if _, err := UnwrapKey(otherKEK, wrapped); err == nil {
			t.Error("UnwrapKey with wrong KEK succeeded, want failure")
		}
	})

	t.Run("tamperFails", func(t *testing.T) {
		wrapped, _ := WrapKey(kek, masterKey)
		wrapped[len(wrapped)-1] ^= 0xFF // flip a bit in the tag
		if _, err := UnwrapKey(kek, wrapped); err == nil {
			t.Error("UnwrapKey of tampered ciphertext succeeded, want failure")
		}
	})

	t.Run("invalidKEKSize", func(t *testing.T) {
		if _, err := WrapKey([]byte("short"), masterKey); err != ErrInvalidKeySize {
			t.Errorf("WrapKey err = %v, want ErrInvalidKeySize", err)
		}
		if _, err := UnwrapKey([]byte("short"), []byte("whatever")); err != ErrInvalidKeySize {
			t.Errorf("UnwrapKey err = %v, want ErrInvalidKeySize", err)
		}
	})

	t.Run("invalidMasterKeySize", func(t *testing.T) {
		if _, err := WrapKey(kek, []byte("short")); err != ErrInvalidKeySize {
			t.Errorf("WrapKey err = %v, want ErrInvalidKeySize", err)
		}
	})
}
