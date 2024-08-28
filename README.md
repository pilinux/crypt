# crypt

Package crypt provides functions for encrypting and decrypting data
using various cryptographic algorithms, including RSA and AES.

This package is designed to simplify the process of securely encrypting
and decrypting data following industry standards. It includes functions
for key generation, encryption, and decryption using well-established
cryptographic primitives.

## Usage

- [AES](_example/aes/main.go)
- [ChaCha20-Poly1305 AEAD](_example/chacha20poly1305/main.go)
- [XChaCha20-Poly1305 AEAD](_example/xchacha20poly1305/main.go)
- [RSA](_example/rsa/main.go)
- [Hashing](_example/hashing/main.go)

## Generate RSA Keys

### 256-byte

```bash
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

### 384-byte

```bash
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:3072
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

### 512-byte

```bash
openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

## LICENSE

[license](LICENSE)
