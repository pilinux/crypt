# crypt

> Batteries-included encryption for Go: AEAD ciphers, RSA, and a ready-made
> envelope-encryption scheme, all behind a small, hard-to-misuse API.

[![Go Reference][1]][2]
[![DeepWiki][3]][4]
[![CodeQL][5]](https://github.com/pilinux/crypt/actions/workflows/codeql-analysis.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)][6]

`crypt` wraps Go's standard `crypto` packages and `golang.org/x/crypto` so you
can encrypt and decrypt data with well-established primitives without writing
the fiddly plumbing yourself. Every function authenticates its output, generates
nonces for you, and returns plain `[]byte` / `string` values.

## Features

- **AES-GCM**: AES-128/192/256 authenticated encryption.
- **ChaCha20-Poly1305**: fast AEAD with a 96-bit nonce.
- **XChaCha20-Poly1305**: AEAD with a 192-bit nonce, safe for huge numbers of
  messages under one key.
- **RSA-OAEP**: public-key encryption with SHA-256 (default) or SHA-512.
- **Base64 helpers**: Std, RawStd, URL and RawURL encoders/decoders.
- **`envelope` subpackage**: a complete KEK/DEK envelope-encryption scheme for
  protecting many records under a single rotatable secret.

## Install

```bash
go get github.com/pilinux/crypt
```

Requires **Go 1.25+**. The only external dependency is `golang.org/x/crypto`.

## Quick start

### Symmetric encryption (AES-256-GCM)

```go
package main

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/pilinux/crypt"
)

func main() {
	// 1. Derive a 32-byte key. crypt never derives keys for you;
	//    bring your own KDF (here: Argon2id over a passphrase).
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte("s3cr3t-passphrase"), salt, 2, 64*1024, 2, 32)

	// 2. Encrypt. A random nonce is generated and prepended to the
	//    ciphertext, so you only ever store a single blob.
	ciphertext, err := crypt.EncryptAesGcmWithNonceAppended(key, "attack at dawn")
	if err != nil {
		panic(err)
	}

	// 3. Decrypt. This also verifies authenticity: any tampering
	//    (or a wrong key) returns an error instead of garbage.
	plaintext, err := crypt.DecryptAesGcmWithNonceAppended(key, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext) // attack at dawn
}
```

Every symmetric cipher follows the same four-way naming pattern, so once you
know one you know them all:

| Variant | Input / output | Nonce |
| --- | --- | --- |
| `Encrypt<Cipher>` | `string` | returned separately |
| `EncryptByte<Cipher>` | `[]byte` | returned separately |
| `Encrypt<Cipher>WithNonceAppended` | `string` | prepended to ciphertext |
| `EncryptByte<Cipher>WithNonceAppended` | `[]byte` | prepended to ciphertext |

Swap `EncryptAesGcm` for `EncryptXChacha20poly1305` (or the ChaCha20 variant) to
change algorithms; the shape is identical.

### Public-key encryption (RSA-OAEP)

```go
// publicKeyPEM / privateKeyPEM are strings loaded from .pem files
// (PKIX "PUBLIC KEY" and PKCS#8 "PRIVATE KEY" blocks; see below).

enc := crypt.NewEncoder(publicKeyPEM)
if enc.Err != nil {
	panic(enc.Err) // the constructor reports PEM problems via .Err
}

ciphertext, err := enc.EncryptRSA("attack at dawn")
if err != nil {
	panic(err)
}

dec := crypt.NewDecoder(privateKeyPEM)
if dec.Err != nil {
	panic(dec.Err)
}

plaintext, err := dec.DecryptRSA(ciphertext)
if err != nil {
	panic(err)
}

// Want SHA-512 instead of the SHA-256 default? Set it on both sides:
//   enc.HashAlg = crypt.SHA512
//   dec.HashAlg = crypt.SHA512
```

### Envelope encryption (many records, one rotatable secret)

Use the [`envelope`](https://pkg.go.dev/github.com/pilinux/crypt/envelope)
subpackage when you need to protect lots of items (rows, files, fields) and be
able to rotate the top-level secret without re-encrypting everything.

```go
package main

import (
	"fmt"
	"os"

	"github.com/pilinux/crypt/envelope"
)

func main() {
	// Configure once with your app's domain-separation labels.
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
	})

	// Bootstrap: derive a key-encryption key (KEK) from a rotatable secret,
	// then generate a master key and store it *wrapped*. (Errors omitted
	// for brevity; handle them in real code.)
	// The secret must be machine-generated randomness, >= 32 chars
	// (e.g. `openssl rand -hex 32`), never a human-chosen passphrase.
	kek, _ := scheme.DeriveKEK(os.Getenv("ENCRYPTION_SECRET"))
	masterKey, _ := envelope.GenerateMasterKey()
	wrapped, _ := envelope.WrapKey(kek, masterKey) // persist `wrapped`, not masterKey
	_ = wrapped

	// Per item: seal to a base64 token, then open it back.
	token, _ := scheme.SealString(masterKey, "top secret")
	plain, _ := scheme.OpenString(masterKey, token)

	fmt.Println(plain) // top secret

	// Optional context binding: authenticate the record/field the token
	// belongs to, so valid tokens cannot be swapped between rows.
	bound, _ := scheme.SealStringAAD(masterKey, "top secret", []byte("user:42:note"))
	_, err := scheme.OpenStringAAD(masterKey, bound, []byte("user:7:note"))
	fmt.Println(err != nil) // wrong context fails to decrypt
}
```

Under the hood every item gets a fresh per-item sub-key (HKDF) and its own
random nonce, so a nonce can never repeat under the same key.
The envelope header is authenticated, and every `Seal*`/`Open*` function
has an `AAD` variant that additionally authenticates caller-supplied context.

## Choosing an algorithm

| If you want to… | Reach for | Key |
| --- | --- | --- |
| Encrypt data with a key you already hold or derive | **AES-256-GCM** or **XChaCha20-Poly1305** | 32 bytes |
| Encrypt many messages under one key without nonce worries | **XChaCha20-Poly1305** | 32 bytes |
| Let someone encrypt *to you* using your public key | **RSA-OAEP** | PEM key pair |
| Protect many records under one rotatable secret | **`envelope`** subpackage | derived |

## API at a glance

| Area | Key functions |
| --- | --- |
| AES-GCM (`aes.go`) | `EncryptAesGcm` / `DecryptAesGcm` (+ `Byte` and `WithNonceAppended` variants) |
| ChaCha20-Poly1305 (`chaCha20.go`) | `EncryptChacha20poly1305` / `DecryptChacha20poly1305` (96-bit nonce) |
| XChaCha20-Poly1305 (`chaCha20.go`) | `EncryptXChacha20poly1305` / `DecryptXChacha20poly1305` (192-bit nonce) |
| RSA-OAEP (`rsa.go`) | `Encoder.EncryptRSA` / `Decoder.DecryptRSA` (+ `Byte` variants) |
| Base64 (`base64.go`) | `Encoder.ToBase64*` / `Decoder.FromBase64*` (Std, RawStd, URL, RawURL) |
| Envelope (`envelope/`) | `Scheme.Seal*`/`Open*` (+ `AAD` variants), `DeriveKEK`, `WrapKey`/`UnwrapKey`, `Zero`, `Sha256Hex`, `RandomHex` |

The ChaCha20/XChaCha20 `Byte...WithNonceAppended` functions also come in
`...AAD` forms that bind caller-supplied associated data (authenticated, not
encrypted) into the ciphertext.

Full, always-current reference lives on
[pkg.go.dev](https://pkg.go.dev/github.com/pilinux/crypt).

## Runnable examples

Each folder under [`_example`](_example) is a standalone program you can run
with `go run ./_example/<name>`:

- [AES](_example/aes/main.go)
- [ChaCha20-Poly1305 AEAD](_example/chacha20poly1305/main.go)
- [XChaCha20-Poly1305 AEAD](_example/xchacha20poly1305/main.go)
- [RSA](_example/rsa/main.go)
- [Hashing](_example/hashing/main.go)
- [Envelope encryption at rest](_example/envelope/main.go)

## Generate RSA keys

RSA works with a PKIX public key (`PUBLIC KEY`) and a PKCS#8 private key
(`PRIVATE KEY`): exactly what these OpenSSL commands produce.

### RSA-2048 (256-byte)

```bash
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

### RSA-3072 (384-byte)

```bash
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:3072
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

### RSA-4096 (512-byte)

```bash
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

## Security notes

- **Bring your own key derivation.** `crypt` encrypts with the key you give it;
  it never derives one. Use Argon2id for passwords and HKDF for high-entropy
  secrets (the `envelope` subpackage does the latter for you).
- **The envelope secret must be machine-generated.** `DeriveKEK` uses HKDF,
  which does no password stretching: generate `ENCRYPTION_SECRET` with
  `openssl rand -hex 32` (or similar) and never use a human-chosen passphrase.
  A guessable secret can be brute-forced offline from the wrapped master key.
- **Key sizes.** AES accepts 16/24/32-byte keys; ChaCha20 and XChaCha20 require
  exactly 32 bytes.
- **Never reuse a (key, nonce) pair.** Nonces come from `crypto/rand`. When
  encrypting many items under one key, prefer XChaCha20-Poly1305 or the
  `envelope` scheme, which give each item its own key or a large random nonce.
- **Everything is authenticated.** All AEAD modes and RSA-OAEP fail closed:
  tampered ciphertext or a wrong key returns an error, never partial plaintext.
- **RSA key formats.** The public key must be a PKIX `PUBLIC KEY` block and the
  private key a PKCS#8 `PRIVATE KEY` block. Always check `.Err` right after
  `NewEncoder` / `NewDecoder`.

## Development

```bash
go test -race -cover ./...   # unit tests, race detector, coverage
go vet ./...                 # static analysis
golangci-lint run ./...      # aggregate linters
```

## License

MIT. See [LICENSE][6].

[1]: https://pkg.go.dev/badge/github.com/pilinux/crypt
[2]: https://pkg.go.dev/github.com/pilinux/crypt
[3]: https://deepwiki.com/badge.svg
[4]: https://deepwiki.com/pilinux/crypt
[5]: https://github.com/pilinux/crypt/actions/workflows/codeql-analysis.yml/badge.svg
[6]: LICENSE
