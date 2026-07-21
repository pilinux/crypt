// Package envelope implements a small, self-contained envelope-encryption
// scheme layered on top of the low-level AEAD primitives in
// github.com/pilinux/crypt. It lets an application protect many independent
// items (strings, numbers, files) under a single rotatable secret without
// re-implementing the tedious key-management plumbing each time.
//
// # Two-layer (envelope) key model
//
//   - KEK (key-encryption key): derived from a high-entropy application secret
//     (typically an ENCRYPTION_SECRET env value) via HKDF-SHA256. It never
//     encrypts user data directly; it only wraps (encrypts) the master key.
//     Rotating the secret therefore means re-wrapping a single stored value
//     instead of re-encrypting every record. See [Scheme.DeriveKEK], [WrapKey]
//     and [UnwrapKey].
//
//   - Master key (DEK, data-encryption key): a random 32-byte key generated
//     once and stored in wrapped (KEK-encrypted) form. It is the key that
//     ultimately protects all user data. See [GenerateMasterKey].
//
// # Using the salt "smartly"
//
// The master key is never handed to XChaCha20-Poly1305 directly. For every
// individual item a fresh random salt is generated and a unique per-item
// sub-key is derived from the master key and that salt with HKDF-SHA256 (see
// [Scheme.DeriveSubKey]). This adds real security on top of the AEAD:
//
//   - every item is encrypted under a different key, so a nonce collision in
//     one item can never affect another;
//   - the master key itself is never used as an AEAD key, limiting how much
//     ciphertext is ever produced under a single key.
//
// The salt is not secret; it is stored next to the ciphertext inside the
// envelope so decryption can re-derive the same sub-key.
//
// # Domain separation
//
// The two HKDF "info" labels (see [Config]) provide domain separation between
// KEK and sub-key derivation. They are frozen per application: once data has
// been wrapped or sealed under a given label, changing it re-derives different
// keys and orphans that data. Construct a [Scheme] with your own labels via
// [New], or use [DefaultKEKLabel] / [DefaultSubKeyLabel].
//
// # Ciphertext (envelope) layout
//
//	┌─────────┬──────────┬──────────────┬───────────────────────────────────┐
//	│ version │ saltLen  │ salt         │ XChaCha20-Poly1305 (nonce||AEAD)   │
//	│ 1 byte  │ 1 byte   │ saltLen byte │ 24-byte nonce + ciphertext + tag   │
//	└─────────┴──────────┴──────────────┴───────────────────────────────────┘
package envelope

import (
	"crypto/rand"
	"errors"
)

// Sizes, in bytes, used throughout the envelope scheme.
const (
	// KeySize is the length of the KEK, the master key and every derived
	// sub-key. XChaCha20-Poly1305 requires a 256-bit (32-byte) key.
	KeySize = 32

	// SaltSize is the length of the random per-item HKDF salt.
	SaltSize = 16

	// NonceSize is the XChaCha20-Poly1305 nonce length (192-bit).
	NonceSize = 24

	// TagSize is the Poly1305 authentication tag length.
	TagSize = 16

	// MinSecretLength is the minimum accepted length of the application secret
	// passed to [Scheme.DeriveKEK]. A shorter secret is rejected outright.
	MinSecretLength = 32
)

// Default HKDF domain-separation labels, used when a [Config] leaves a label
// empty. Applications that persist data should pin their own labels via [New]
// so the values live in their own source and never change underneath
// already-wrapped keys.
const (
	// DefaultKEKLabel is the fallback HKDF info label for KEK derivation.
	DefaultKEKLabel = "pilinux/crypt/envelope:kek:v1"

	// DefaultSubKeyLabel is the fallback HKDF info label for sub-key derivation.
	DefaultSubKeyLabel = "pilinux/crypt/envelope:data-subkey:v1"
)

const (
	// envelopeVersion tags the envelope format so an unknown or legacy blob is
	// rejected explicitly instead of being decrypted with wrong assumptions.
	envelopeVersion byte = 0x01

	// envelopeHeaderSize is the fixed part of the envelope header: the version
	// byte plus the salt-length byte.
	envelopeHeaderSize = 2
)

// Errors returned by the package. They are intentionally generic so a calling
// HTTP layer never leaks internal detail to API consumers.
var (
	// ErrSecretTooShort is returned when the secret is below MinSecretLength.
	ErrSecretTooShort = errors.New("envelope: secret must be at least 32 characters")

	// ErrInvalidKeySize is returned when a key argument is not KeySize bytes.
	ErrInvalidKeySize = errors.New("envelope: key must be 32 bytes")

	// ErrInvalidSaltSize is returned when a salt argument is not SaltSize bytes.
	ErrInvalidSaltSize = errors.New("envelope: salt must be 16 bytes")

	// ErrBadEnvelope is returned when a blob is not a well-formed envelope.
	ErrBadEnvelope = errors.New("envelope: malformed ciphertext envelope")

	// ErrNotAnInteger is returned by [Scheme.OpenInt64] when the token decrypts
	// successfully but its plaintext is not a base-10 integer. The underlying
	// strconv error is deliberately discarded because it would embed the
	// decrypted plaintext in the error message.
	ErrNotAnInteger = errors.New("envelope: sealed value is not an integer")
)

// Config configures the HKDF domain-separation labels of a [Scheme]. An empty
// label falls back to the corresponding package default.
type Config struct {
	// KEKLabel is the HKDF info label for deriving the KEK from the secret.
	KEKLabel string

	// SubKeyLabel is the HKDF info label for deriving per-item sub-keys.
	SubKeyLabel string
}

// Scheme carries the domain-separation labels used by the label-dependent
// operations ([Scheme.DeriveKEK], [Scheme.DeriveSubKey] and the Seal/Open
// family). It is immutable after construction and safe for concurrent use.
type Scheme struct {
	kekLabel    string
	subKeyLabel string
}

// New returns a [Scheme] using the labels in cfg, falling back to
// [DefaultKEKLabel] / [DefaultSubKeyLabel] for any label left empty.
func New(cfg Config) *Scheme {
	if cfg.KEKLabel == "" {
		cfg.KEKLabel = DefaultKEKLabel
	}
	if cfg.SubKeyLabel == "" {
		cfg.SubKeyLabel = DefaultSubKeyLabel
	}
	return &Scheme{
		kekLabel:    cfg.KEKLabel,
		subKeyLabel: cfg.SubKeyLabel,
	}
}

// Default returns a [Scheme] that uses the package default labels. It is
// shorthand for New(Config{}).
func Default() *Scheme {
	return New(Config{})
}

// randomBytes returns n cryptographically secure random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// packEnvelope assembles the on-the-wire envelope from a salt and the
// XChaCha20-Poly1305 ciphertext (which already carries its nonce prepended).
func packEnvelope(salt, ciphertext []byte) ([]byte, error) {
	if len(salt) == 0 || len(salt) > 255 {
		return nil, ErrInvalidSaltSize
	}

	out := make([]byte, envelopeHeaderSize+len(salt)+len(ciphertext))
	out[0] = envelopeVersion
	// the salt length is guaranteed to be in 1..255 by the guard above, so the
	// conversion to a single byte cannot overflow.
	out[1] = byte(len(salt)) // #nosec G115
	copy(out[envelopeHeaderSize:], salt)
	copy(out[envelopeHeaderSize+len(salt):], ciphertext)
	return out, nil
}

// unpackEnvelope splits an envelope back into its salt and ciphertext. It
// rejects any blob whose version byte or length does not match the format.
func unpackEnvelope(blob []byte) (salt, ciphertext []byte, err error) {
	if len(blob) < envelopeHeaderSize {
		return nil, nil, ErrBadEnvelope
	}
	if blob[0] != envelopeVersion {
		return nil, nil, ErrBadEnvelope
	}

	saltLen := int(blob[1])
	if saltLen == 0 {
		return nil, nil, ErrBadEnvelope
	}

	// the blob must hold the header, the full salt and at least a
	// nonce + tag worth of ciphertext, otherwise it cannot be authentic.
	minLen := envelopeHeaderSize + saltLen + NonceSize + TagSize
	if len(blob) < minLen {
		return nil, nil, ErrBadEnvelope
	}

	salt = blob[envelopeHeaderSize : envelopeHeaderSize+saltLen]
	ciphertext = blob[envelopeHeaderSize+saltLen:]
	return salt, ciphertext, nil
}
