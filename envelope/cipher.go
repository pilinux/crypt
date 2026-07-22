package envelope

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/pilinux/crypt"
)

// int64WireSize is the fixed plaintext length of a sealed int64: 8-byte
// big-endian two's complement, so every int64 token has the same length and
// the token length cannot leak the magnitude of the value.
const int64WireSize = 8

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
// XChaCha20-Poly1305 ciphertext with the nonce prepended). It is shorthand for
// [Scheme.SealBytesAAD] with a nil AAD; the envelope header is authenticated
// either way.
func (s *Scheme) SealBytes(masterKey, plaintext []byte) ([]byte, error) {
	return s.SealBytesAAD(masterKey, plaintext, nil)
}

// SealBytesAAD is [Scheme.SealBytes] with context binding: aad (associated
// data, e.g. a record ID or field name) is authenticated alongside the
// envelope header, but neither encrypted nor stored. [Scheme.OpenBytesAAD]
// must be given the identical aad, so two tokens sealed with different AAD
// can never be swapped for one another.
func (s *Scheme) SealBytesAAD(masterKey, plaintext, aad []byte) ([]byte, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	subKey, err := s.DeriveSubKey(masterKey, salt)
	if err != nil {
		return nil, err
	}
	defer Zero(subKey)

	header, err := buildHeader(salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypt.EncryptByteXChacha20poly1305WithNonceAppendedAAD(subKey, plaintext, authData(header, aad))
	if err != nil {
		return nil, err
	}

	blob := make([]byte, 0, len(header)+len(ciphertext))
	blob = append(blob, header...)
	blob = append(blob, ciphertext...)
	return blob, nil
}

// OpenBytes decrypts an envelope produced by [Scheme.SealBytes] using the master
// key. It returns an error if the envelope is malformed, the master key is
// wrong or the envelope was tampered with (authentication failure).
func (s *Scheme) OpenBytes(masterKey, blob []byte) ([]byte, error) {
	return s.OpenBytesAAD(masterKey, blob, nil)
}

// OpenBytesAAD decrypts an envelope produced by [Scheme.SealBytesAAD]. The aad
// must be identical to the value passed at sealing time; any mismatch (or a
// missing AAD) fails authentication.
func (s *Scheme) OpenBytesAAD(masterKey, blob, aad []byte) ([]byte, error) {
	header, salt, ciphertext, err := unpackEnvelope(blob)
	if err != nil {
		return nil, err
	}

	subKey, err := s.DeriveSubKey(masterKey, salt)
	if err != nil {
		return nil, err
	}
	defer Zero(subKey)

	return crypt.DecryptByteXChacha20poly1305WithNonceAppendedAAD(subKey, ciphertext, authData(header, aad))
}

// SealString encrypts a plaintext string and returns the envelope as a standard
// base64 token suitable for placing in a JSON response. It is shorthand for
// [Scheme.SealStringAAD] with a nil AAD.
func (s *Scheme) SealString(masterKey []byte, plaintext string) (string, error) {
	return s.SealStringAAD(masterKey, plaintext, nil)
}

// SealStringAAD is [Scheme.SealString] with context binding; see
// [Scheme.SealBytesAAD] for how the aad is used.
func (s *Scheme) SealStringAAD(masterKey []byte, plaintext string, aad []byte) (string, error) {
	blob, err := s.SealBytesAAD(masterKey, []byte(plaintext), aad)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// OpenString decrypts a base64 token produced by [Scheme.SealString] back into
// the original plaintext string.
func (s *Scheme) OpenString(masterKey []byte, token string) (string, error) {
	return s.OpenStringAAD(masterKey, token, nil)
}

// OpenStringAAD decrypts a base64 token produced by [Scheme.SealStringAAD];
// the aad must match the value used at sealing time.
func (s *Scheme) OpenStringAAD(masterKey []byte, token string, aad []byte) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", ErrBadEnvelope
	}

	plaintext, err := s.OpenBytesAAD(masterKey, blob, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SealInt64 encrypts a signed integer, using the exact same envelope machinery
// as [Scheme.SealString]. The value is encoded in fixed-width 8-byte
// big-endian form before sealing, so every int64 token has the same length
// and the token length does not leak the magnitude of the value. It is
// shorthand for [Scheme.SealInt64AAD] with a nil AAD.
func (s *Scheme) SealInt64(masterKey []byte, n int64) (string, error) {
	return s.SealInt64AAD(masterKey, n, nil)
}

// SealInt64AAD is [Scheme.SealInt64] with context binding; see
// [Scheme.SealBytesAAD] for how the aad is used. Sealing different value
// types under distinct AADs (e.g. "user:42:age") also prevents an int64 token
// from being opened as some other field's string.
func (s *Scheme) SealInt64AAD(masterKey []byte, n int64, aad []byte) (string, error) {
	var buf [int64WireSize]byte
	// the int64 -> uint64 conversion is the standard lossless two's-complement
	// bit-pattern round-trip, reversed exactly in OpenInt64AAD.
	binary.BigEndian.PutUint64(buf[:], uint64(n)) // #nosec G115

	blob, err := s.SealBytesAAD(masterKey, buf[:], aad)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// OpenInt64 decrypts a token produced by [Scheme.SealInt64] back into the
// original integer.
func (s *Scheme) OpenInt64(masterKey []byte, token string) (int64, error) {
	return s.OpenInt64AAD(masterKey, token, nil)
}

// OpenInt64AAD decrypts a token produced by [Scheme.SealInt64AAD]; the aad
// must match the value used at sealing time. It returns [ErrNotAnInteger] if
// the token authenticates but its plaintext is not the fixed-width 8-byte
// integer encoding.
func (s *Scheme) OpenInt64AAD(masterKey []byte, token string, aad []byte) (int64, error) {
	blob, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, ErrBadEnvelope
	}

	plaintext, err := s.OpenBytesAAD(masterKey, blob, aad)
	if err != nil {
		return 0, err
	}
	if len(plaintext) != int64WireSize {
		return 0, ErrNotAnInteger
	}

	// reverse of the conversion in SealInt64AAD; cannot overflow.
	return int64(binary.BigEndian.Uint64(plaintext)), nil // #nosec G115
}
