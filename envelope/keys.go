package envelope

import (
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/pilinux/crypt"
)

// DeriveKEK derives the 32-byte key-encryption key (KEK) from the application
// secret using HKDF-SHA256 with the Scheme's KEK label.
//
// The secret must contain at least [MinSecretLength] characters of entropy. The
// derivation is deterministic: the same secret always yields the same KEK,
// which is what makes secret rotation detectable (a KEK that can no longer
// unwrap the stored master key means the secret changed).
func (s *Scheme) DeriveKEK(secret string) ([]byte, error) {
	if len(secret) < MinSecretLength {
		return nil, ErrSecretTooShort
	}

	// HKDF with a nil salt is appropriate here: the input already carries high
	// entropy and the info label provides domain separation.
	return hkdf.Key(sha256.New, []byte(secret), nil, s.kekLabel, KeySize)
}

// GenerateMasterKey returns a new random 32-byte master key (DEK). It is called
// exactly once, when no master key exists yet.
func GenerateMasterKey() ([]byte, error) {
	return randomBytes(KeySize)
}

// WrapKey encrypts the master key with the KEK for storage at rest, using
// XChaCha20-Poly1305 with the nonce prepended to the ciphertext.
func WrapKey(kek, masterKey []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(masterKey) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return crypt.EncryptByteXChacha20poly1305WithNonceAppended(kek, masterKey)
}

// UnwrapKey decrypts a KEK-wrapped master key produced by [WrapKey]. A non-nil
// error means the KEK is wrong (e.g. the secret changed) or the stored value
// was tampered with.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return crypt.DecryptByteXChacha20poly1305WithNonceAppended(kek, wrapped)
}
