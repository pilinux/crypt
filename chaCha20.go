package crypt

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptByteChacha20poly1305 encrypts and authenticates the given message (bytes) with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
func EncryptByteChacha20poly1305(key []byte, input []byte) (ciphertext []byte, nonce []byte, err error) {
	// create a new ChaCha20-Poly1305 AEAD using the given 256-bit key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
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

// EncryptChacha20poly1305 encrypts and authenticates the given message (string) with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
func EncryptChacha20poly1305(key []byte, text string) (ciphertext []byte, nonce []byte, err error) {
	return EncryptByteChacha20poly1305(key, []byte(text))
}

// DecryptByteChacha20poly1305 decrypts and authenticates the given ciphertext with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
func DecryptByteChacha20poly1305(key, nonce, ciphertext []byte) (plaintext []byte, err error) {
	// create a new ChaCha20-Poly1305 AEAD using the given 256-bit key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
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

// DecryptChacha20poly1305 decrypts and authenticates the given ciphertext with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
func DecryptChacha20poly1305(key, nonce, ciphertext []byte) (text string, err error) {
	// decrypt the data
	plaintext, err := DecryptByteChacha20poly1305(key, nonce, ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}

// EncryptByteChacha20poly1305WithNonceAppended encrypts and authenticates the given message (bytes) with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptByteChacha20poly1305WithNonceAppended(key []byte, input []byte) (ciphertext []byte, err error) {
	ciphertext, nonce, err := EncryptByteChacha20poly1305(key, input)
	if err != nil {
		return
	}

	ciphertext = append(nonce, ciphertext...)
	return
}

// EncryptChacha20poly1305WithNonceAppended encrypts and authenticates the given message (string) with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptChacha20poly1305WithNonceAppended(key []byte, text string) (ciphertext []byte, err error) {
	return EncryptByteChacha20poly1305WithNonceAppended(key, []byte(text))
}

// DecryptByteChacha20poly1305WithNonceAppended decrypts and authenticates the given ciphertext with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptByteChacha20poly1305WithNonceAppended(key, ciphertext []byte) (plaintext []byte, err error) {
	nonceSize := chacha20poly1305.NonceSize
	if len(ciphertext) < nonceSize {
		err = errors.New("ciphertext is too short")
		return
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return DecryptByteChacha20poly1305(key, nonce, ciphertext)
}

// DecryptChacha20poly1305WithNonceAppended decrypts and authenticates the given ciphertext with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptChacha20poly1305WithNonceAppended(key, ciphertext []byte) (text string, err error) {
	plaintext, err := DecryptByteChacha20poly1305WithNonceAppended(key, ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}

// EncryptByteXChacha20poly1305 encrypts and authenticates the given message (bytes) with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
func EncryptByteXChacha20poly1305(key []byte, input []byte) (ciphertext []byte, nonce []byte, err error) {
	// create a new XChaCha20-Poly1305 AEAD using the given 256-bit key
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
		return
	}

	// generate a 192-bit random nonce
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

// EncryptXChacha20poly1305 encrypts and authenticates the given message (string) with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
func EncryptXChacha20poly1305(key []byte, text string) (ciphertext []byte, nonce []byte, err error) {
	return EncryptByteXChacha20poly1305(key, []byte(text))
}

// DecryptByteXChacha20poly1305 decrypts and authenticates the given ciphertext with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
func DecryptByteXChacha20poly1305(key, nonce, ciphertext []byte) (plaintext []byte, err error) {
	// create a new XChaCha20-Poly1305 AEAD using the given 256-bit key
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
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

// DecryptXChacha20poly1305 decrypts and authenticates the given ciphertext with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
func DecryptXChacha20poly1305(key, nonce, ciphertext []byte) (text string, err error) {
	// decrypt the data
	plaintext, err := DecryptByteXChacha20poly1305(key, nonce, ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}

// EncryptByteXChacha20poly1305WithNonceAppended encrypts and authenticates the given message (bytes) with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptByteXChacha20poly1305WithNonceAppended(key []byte, input []byte) (ciphertext []byte, err error) {
	ciphertext, nonce, err := EncryptByteXChacha20poly1305(key, input)
	if err != nil {
		return
	}
	ciphertext = append(nonce, ciphertext...)
	return
}

// EncryptXChacha20poly1305WithNonceAppended encrypts and authenticates the given message (string) with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptXChacha20poly1305WithNonceAppended(key []byte, text string) (ciphertext []byte, err error) {
	return EncryptByteXChacha20poly1305WithNonceAppended(key, []byte(text))
}

// DecryptByteXChacha20poly1305WithNonceAppended decrypts and authenticates the given ciphertext with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptByteXChacha20poly1305WithNonceAppended(key, ciphertext []byte) (plaintext []byte, err error) {
	nonceSize := chacha20poly1305.NonceSizeX
	if len(ciphertext) < nonceSize {
		err = errors.New("ciphertext is too short")
		return
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return DecryptByteXChacha20poly1305(key, nonce, ciphertext)
}

// DecryptXChacha20poly1305WithNonceAppended decrypts and authenticates the given ciphertext with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptXChacha20poly1305WithNonceAppended(key, ciphertext []byte) (text string, err error) {
	plaintext, err := DecryptByteXChacha20poly1305WithNonceAppended(key, ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}
