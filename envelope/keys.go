package envelope

import (
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/pilinux/crypt"
)

// DeriveKEK derives the 32-byte key-encryption key (KEK) from the application
// secret using HKDF-SHA256 with the Scheme's KEK label.
//
// The secret must be machine-generated randomness of at least
// [MinSecretLength] characters (e.g. the output of `openssl rand -hex 32`),
// never a human-chosen passphrase: the derivation is plain HKDF with no
// password stretching, so a guessable secret can be brute-forced offline by
// anyone holding the wrapped master key.
//
// The derivation is deterministic: the same secret always yields the same KEK,
// which is what makes secret rotation detectable (a KEK that can no longer
// unwrap the stored master key means the secret changed). The KEK is only
// needed to wrap or unwrap the master key; wipe it with [Zero] afterwards.
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
// error means the KEK is wrong (e.g. the secret changed), the stored value was
// tampered with, or the wrapped plaintext is not a 32-byte key.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, ErrInvalidKeySize
	}

	masterKey, err := crypt.DecryptByteXChacha20poly1305WithNonceAppended(kek, wrapped)
	if err != nil {
		return nil, err
	}
	if len(masterKey) != KeySize {
		// authentic under the KEK but not a master key: the blob was not
		// produced by WrapKey, so refuse to hand its plaintext out as one.
		Zero(masterKey)
		return nil, ErrInvalidKeySize
	}
	return masterKey, nil
}

// Zero overwrites b with zeros, removing key material from memory. Call it on
// the KEK, the master key and any explicitly derived sub-key as soon as the
// value is no longer needed; the Seal/Open functions already wipe the
// sub-keys they derive internally. Wiping is best effort: the runtime or
// cipher internals may hold transient copies that cannot be reached from Go
// code.
func Zero(b []byte) {
	clear(b)
}
