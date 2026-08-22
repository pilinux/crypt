// Package envelope implements a small, self-contained envelope-encryption
// scheme layered on top of the low-level AEAD primitives in
// github.com/pilinux/crypt. It lets an application protect many independent
// items (strings, numbers, files) under a single rotatable secret without
// re-implementing the tedious key-management plumbing each time.
//
// # Two-layer (envelope) key model
//
//   - KEK (key-encryption key): derived from a high-entropy application secret
//     (typically an ENCRYPTION_SECRET env value; machine-generated, never a
//     human-chosen passphrase) via HKDF-SHA256. It never
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
//
// The header (version, saltLen, salt) is authenticated as AEAD additional
// data, so not a single header byte can be altered without decryption
// failing.
//
// # Streaming large inputs
//
// The Seal/Open functions above hold the whole item in memory. Inputs that do
// not fit, such as multi-gigabyte files or request bodies, go through the
// streaming API instead ([Scheme.SealWriter], [Scheme.OpenReader],
// [Scheme.SealFile], [Scheme.SealStream] and friends), which seals one chunk
// at a time under the same key model and keeps memory use at one chunk:
//
//	header || chunk 0 || chunk 1 || ... || final chunk
//
//	where header = version(1) || saltLen(1) || salt || chunkSize(4) || noncePrefix(15)
//	and   chunk  = XChaCha20-Poly1305(chunkSize bytes of plaintext)
//
// Every chunk is sealed under the same per-stream sub-key with the nonce
// noncePrefix || counter || finalFlag, so chunks cannot be reordered,
// duplicated, dropped or the stream cut short: the counter pins each chunk to
// its position and the flag marks the end. The header, and any caller-supplied
// AAD, is authenticated with every chunk.
//
// What a stream costs:
//
//	memory: one chunk, whatever the input size. The buffer is allocated once
//	        per stream and reused, and every chunk is sealed and opened in
//	        place, so nothing is allocated per chunk.
//	size:   len(header) + plaintext + TagSize*chunks bytes, where
//	        chunks = ceil(plaintext/chunkSize), at least one. That is 37 bytes
//	        plus 16 bytes per chunk: 160 KiB of tags on a 10 GB file at the
//	        default chunk size, about 0.0015%.
//
// Bigger chunks buy less overhead at the price of more memory per stream; the
// default is a middle ground, [Config.ChunkSize] moves it.
//
// # Context binding (AAD)
//
// Every Seal/Open function has an AAD variant ([Scheme.SealBytesAAD],
// [Scheme.OpenStringAAD], ...) that additionally authenticates a
// caller-supplied byte string, for example a record ID or field name. Two
// tokens sealed under the same master key but different AAD are not
// interchangeable: opening with the wrong (or a missing) AAD fails. Use this
// to stop an attacker with write access to the datastore from swapping valid
// tokens between rows or fields. The plain variants are shorthand for a nil
// AAD; the envelope header is authenticated either way.
//
// # Key hygiene
//
// [Zero] wipes key material once it is no longer needed. The scheme wipes
// every internally derived per-item sub-key itself; wiping the KEK and the
// unwrapped master key is the caller's job, since only the caller knows their
// lifetime. Wiping is best effort: the runtime or cipher internals may hold
// transient copies that cannot be reached from Go code.
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
	//
	// The length check is a floor, not a measure of quality: the secret must
	// be machine-generated randomness (e.g. `openssl rand -hex 32`), never a
	// human-chosen passphrase, because KEK derivation applies no password
	// stretching.
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
	// Version 0x01 (current): the header is authenticated as AEAD additional
	// data and int64 values are sealed in fixed-width 8-byte big-endian form.
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
	// successfully but its plaintext is not the fixed-width 8-byte encoding
	// produced by [Scheme.SealInt64] (for example a token that was sealed by
	// [Scheme.SealString]).
	ErrNotAnInteger = errors.New("envelope: sealed value is not an integer")
)

// Config configures the HKDF domain-separation labels of a [Scheme]. An empty
// label falls back to the corresponding package default.
type Config struct {
	// KEKLabel is the HKDF info label for deriving the KEK from the secret.
	KEKLabel string

	// SubKeyLabel is the HKDF info label for deriving per-item sub-keys.
	SubKeyLabel string

	// ChunkSize is the plaintext chunk size of the streaming API, in bytes,
	// within [MinChunkSize]..[MaxChunkSize]. Zero falls back to
	// [DefaultChunkSize]; an out-of-range value is reported when a stream is
	// created. Unlike the labels it is not frozen: every stream records its
	// own chunk size, so changing this never orphans sealed data.
	ChunkSize int
}

// Scheme carries the domain-separation labels used by the label-dependent
// operations ([Scheme.DeriveKEK], [Scheme.DeriveSubKey] and the Seal/Open
// family). It is immutable after construction and safe for concurrent use.
type Scheme struct {
	kekLabel    string
	subKeyLabel string
	chunkSize   int
}

// New returns a [Scheme] using the labels in cfg, falling back to
// [DefaultKEKLabel] / [DefaultSubKeyLabel] for any label left empty and to
// [DefaultChunkSize] for an unset chunk size.
func New(cfg Config) *Scheme {
	if cfg.KEKLabel == "" {
		cfg.KEKLabel = DefaultKEKLabel
	}
	if cfg.SubKeyLabel == "" {
		cfg.SubKeyLabel = DefaultSubKeyLabel
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	return &Scheme{
		kekLabel:    cfg.KEKLabel,
		subKeyLabel: cfg.SubKeyLabel,
		chunkSize:   cfg.ChunkSize,
	}
}

// Default returns a [Scheme] that uses the package default labels and chunk
// size. It is shorthand for New(Config{}).
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

// buildHeader assembles the envelope header (version || saltLen || salt) for
// the given salt. The header is stored in the clear at the start of the
// envelope and is also fed to the AEAD as (the leading part of) its
// additional data, so none of its bytes can be altered without decryption
// failing.
func buildHeader(salt []byte) ([]byte, error) {
	if len(salt) == 0 || len(salt) > 255 {
		return nil, ErrInvalidSaltSize
	}

	header := make([]byte, envelopeHeaderSize+len(salt))
	header[0] = envelopeVersion
	// the salt length is guaranteed to be in 1..255 by the guard above, so the
	// conversion to a single byte cannot overflow.
	header[1] = byte(len(salt)) // #nosec G115
	copy(header[envelopeHeaderSize:], salt)
	return header, nil
}

// authData returns the byte string authenticated (but not encrypted) by the
// AEAD: the envelope header followed by the caller-supplied AAD. A nil or
// empty aad authenticates the header alone.
func authData(header, aad []byte) []byte {
	if len(aad) == 0 {
		return header
	}

	out := make([]byte, 0, len(header)+len(aad))
	out = append(out, header...)
	return append(out, aad...)
}

// unpackEnvelope splits an envelope back into its header, salt and
// ciphertext (all aliasing blob). It rejects any blob whose version byte or
// length does not match the format.
func unpackEnvelope(blob []byte) (header, salt, ciphertext []byte, err error) {
	if len(blob) < envelopeHeaderSize {
		return nil, nil, nil, ErrBadEnvelope
	}
	if blob[0] != envelopeVersion {
		return nil, nil, nil, ErrBadEnvelope
	}

	saltLen := int(blob[1])
	if saltLen == 0 {
		return nil, nil, nil, ErrBadEnvelope
	}

	// the blob must hold the header, the full salt and at least a
	// nonce + tag worth of ciphertext, otherwise it cannot be authentic.
	minLen := envelopeHeaderSize + saltLen + NonceSize + TagSize
	if len(blob) < minLen {
		return nil, nil, nil, ErrBadEnvelope
	}

	header = blob[:envelopeHeaderSize+saltLen]
	salt = header[envelopeHeaderSize:]
	ciphertext = blob[envelopeHeaderSize+saltLen:]
	return header, salt, ciphertext, nil
}
