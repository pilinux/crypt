// Package crypt provides small, hard-to-misuse helpers for encrypting and
// decrypting data with well-established cryptographic primitives, wrapping the
// standard library and golang.org/x/crypto.
//
// It offers:
//
//   - AES-GCM authenticated encryption (AES-128/192/256);
//   - ChaCha20-Poly1305 (96-bit nonce) and XChaCha20-Poly1305 (192-bit nonce)
//     AEAD;
//   - RSA-OAEP public-key encryption with SHA-256 or SHA-512;
//   - Base64 encoding helpers (standard, raw, and URL alphabets).
//
// # Symmetric API conventions
//
// Each symmetric cipher exposes a consistent set of functions: a string form
// (for example [EncryptAesGcm]) and a byte form ([EncryptByteAesGcm]), and each
// of those has a plain variant that returns the nonce separately plus a
// WithNonceAppended variant that prepends the freshly generated nonce to the
// ciphertext, so the whole message can be stored as a single value. Every
// encryption generates its nonce with crypto/rand, and every decryption
// authenticates the ciphertext, returning an error on tampering or a wrong key.
//
// The package does not derive keys. Callers pass a key of the correct length
// (AES accepts 16, 24, or 32 bytes; ChaCha20 and XChaCha20 require 32) and
// should derive keys from passwords with a KDF such as Argon2id.
//
// # Public-key and Base64
//
// RSA-OAEP and the Base64 helpers are methods on the [Encoder] and [Decoder]
// types, which are built from PEM-encoded keys with [NewEncoder] and
// [NewDecoder].
//
// # Higher-level scheme
//
// For envelope encryption with a key hierarchy and a rotatable secret (useful
// for protecting many records at rest), see the subpackage
// [github.com/pilinux/crypt/envelope].
package crypt
