package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Maximum message sizes accepted by AES-GCM with the standard 96-bit nonce.
// Above these bounds crypto/cipher's Seal/Open panic ("message too large for
// GCM"); we reject such inputs with an error instead. The limit (~64 GiB) is
// far above any practical payload and mirrors the stdlib's own guard
// (((1<<32)-2) blocks of 16 bytes, plus the 16-byte tag for ciphertext).
const (
	gcmMaxPlaintextSize  uint64 = ((1 << 32) - 2) * 16 // 64 GiB - 32 bytes
	gcmMaxCiphertextSize uint64 = ((1<<32)-2)*16 + 16  // 64 GiB - 16 bytes
)

// EncryptByteAesGcm encrypts and authenticates the given message (bytes) with AES in GCM mode
// using the given 128, 192 or 256-bit key.
func EncryptByteAesGcm(key []byte, input []byte) (ciphertext []byte, nonce []byte, err error) {
	// create a new AES cipher block
	// the key argument should be the AES key, either 16, 24, or 32 bytes
	// to select AES-128, AES-192, or AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("error creating cipher.Block: %v", err)
		return
	}

	// create a GCM cipher instance
	aead, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
		return
	}

	// reject oversized input so Seal returns an error rather than panicking
	if uint64(len(input)) > gcmMaxPlaintextSize {
		err = errors.New("plaintext too large")
		return
	}

	// generate a 96-bit random nonce
	nonce = make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		err = fmt.Errorf("error generating nonce: %v", err)
		return
	}

	// encrypt the data
	ciphertext = aead.Seal(nil, nonce, input, nil)

	return
}

// EncryptAesGcm encrypts and authenticates the given message (string) with AES in GCM mode
// using the given 128, 192 or 256-bit key.
func EncryptAesGcm(key []byte, text string) (ciphertext []byte, nonce []byte, err error) {
	return EncryptByteAesGcm(key, []byte(text))
}

// DecryptByteAesGcm decrypts and authenticates the given message with AES in GCM mode
// using the given 128, 192 or 256-bit key and 96-bit nonce.
func DecryptByteAesGcm(key, nonce, ciphertext []byte) (plaintext []byte, err error) {
	// create a new AES cipher block
	// the key argument should be the AES key, either 16, 24, or 32 bytes
	// to select AES-128, AES-192, or AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("error creating cipher.Block: %v", err)
		return
	}

	// create a GCM cipher instance
	aead, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
		return
	}

	// reject a wrong-length nonce or oversized ciphertext so Open returns an
	// error rather than panicking on caller-supplied input
	if len(nonce) != aead.NonceSize() {
		err = errors.New("invalid nonce length")
		return
	}
	if uint64(len(ciphertext)) > gcmMaxCiphertextSize {
		err = errors.New("ciphertext too large")
		return
	}

	// decrypt the data
	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = fmt.Errorf("error decrypting data: %v", err)
		return
	}

	return
}

// DecryptAesGcm decrypts and authenticates the given message with AES in GCM mode
// using the given 128, 192 or 256-bit key and 96-bit nonce.
func DecryptAesGcm(key, nonce, ciphertext []byte) (text string, err error) {
	// decrypt the data
	plaintext, err := DecryptByteAesGcm(key, nonce, ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}

// EncryptByteAesGcmWithNonceAppended encrypts and authenticates the given message (bytes) with AES in GCM mode
// using the given 128, 192 or 256-bit key.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptByteAesGcmWithNonceAppended(key []byte, input []byte) (ciphertext []byte, err error) {
	ciphertext, nonce, err := EncryptByteAesGcm(key, input)
	if err != nil {
		return
	}

	ciphertext = append(nonce, ciphertext...)
	return
}

// EncryptAesGcmWithNonceAppended encrypts and authenticates the given message (string) with AES in GCM mode
// using the given 128, 192 or 256-bit key.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptAesGcmWithNonceAppended(key []byte, text string) (ciphertext []byte, err error) {
	return EncryptByteAesGcmWithNonceAppended(key, []byte(text))
}

// DecryptByteAesGcmWithNonceAppended decrypts and authenticates the given ciphertext with AES in GCM mode
// using the given 128, 192 or 256-bit key.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptByteAesGcmWithNonceAppended(key, ciphertext []byte) (plaintext []byte, err error) {
	nonceSize := 12
	if len(ciphertext) < nonceSize {
		err = errors.New("ciphertext is too short")
		return
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return DecryptByteAesGcm(key, nonce, ciphertext)
}

// DecryptAesGcmWithNonceAppended decrypts and authenticates the given ciphertext with AES in GCM mode
// using the given 128, 192 or 256-bit key.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptAesGcmWithNonceAppended(key, ciphertext []byte) (text string, err error) {
	plaintext, err := DecryptByteAesGcmWithNonceAppended(key, ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}
