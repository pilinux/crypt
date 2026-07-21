package envelope

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"strconv"

	"github.com/pilinux/crypt"
)

// GenerateSalt returns a new random per-item salt.
func GenerateSalt() ([]byte, error) {
	return randomBytes(SaltSize)
}

// DeriveSubKey derives a unique 32-byte per-item encryption key from the master
// key and a random salt using HKDF-SHA256 with the Scheme's sub-key label. This
// is the "smart salt" step: the master key is never used as an AEAD key
// directly, and every item ends up with its own key, so a nonce reused across
// two items can never collide under the same key.
func (s *Scheme) DeriveSubKey(masterKey, salt []byte) ([]byte, error) {
	if len(masterKey) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(salt) != SaltSize {
		return nil, ErrInvalidSaltSize
	}
	return hkdf.Key(sha256.New, masterKey, salt, s.subKeyLabel, KeySize)
}

// SealBytes encrypts plaintext with a fresh per-item sub-key derived from the
// master key and returns a self-contained envelope (version, salt and
// XChaCha20-Poly1305 ciphertext with the nonce prepended).
func (s *Scheme) SealBytes(masterKey, plaintext []byte) ([]byte, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	subKey, err := s.DeriveSubKey(masterKey, salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypt.EncryptByteXChacha20poly1305WithNonceAppended(subKey, plaintext)
	if err != nil {
		return nil, err
	}

	return packEnvelope(salt, ciphertext)
}

// OpenBytes decrypts an envelope produced by [Scheme.SealBytes] using the master
// key. It returns an error if the envelope is malformed, the master key is
// wrong or the ciphertext was tampered with (authentication failure).
func (s *Scheme) OpenBytes(masterKey, blob []byte) ([]byte, error) {
	salt, ciphertext, err := unpackEnvelope(blob)
	if err != nil {
		return nil, err
	}

	subKey, err := s.DeriveSubKey(masterKey, salt)
	if err != nil {
		return nil, err
	}

	return crypt.DecryptByteXChacha20poly1305WithNonceAppended(subKey, ciphertext)
}

// SealString encrypts a plaintext string and returns the envelope as a standard
// base64 token suitable for placing in a JSON response.
func (s *Scheme) SealString(masterKey []byte, plaintext string) (string, error) {
	blob, err := s.SealBytes(masterKey, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// OpenString decrypts a base64 token produced by [Scheme.SealString] back into
// the original plaintext string.
func (s *Scheme) OpenString(masterKey []byte, token string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", ErrBadEnvelope
	}

	plaintext, err := s.OpenBytes(masterKey, blob)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SealInt64 encrypts a signed integer by encoding it as its base-10 text and
// sealing that, using the exact same envelope machinery as [Scheme.SealString].
func (s *Scheme) SealInt64(masterKey []byte, n int64) (string, error) {
	return s.SealString(masterKey, strconv.FormatInt(n, 10))
}

// OpenInt64 decrypts a token produced by [Scheme.SealInt64] back into the
// original integer.
func (s *Scheme) OpenInt64(masterKey []byte, token string) (int64, error) {
	text, err := s.OpenString(masterKey, token)
	if err != nil {
		return 0, err
	}

	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, ErrNotAnInteger
	}
	return n, nil
}
