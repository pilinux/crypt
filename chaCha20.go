package crypt

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptChacha20poly1305 encrypts and authenticates the given message with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
func EncryptChacha20poly1305(key []byte, text string) (ciphertext []byte, nonce []byte, err error) {
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

	// data to be encrypted
	data := []byte(text)

	// encrypt the data
	ciphertext = aead.Seal(nil, nonce, data, nil)

	return
}

// DecryptChacha20poly1305 decrypts and authenticates the given message with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
func DecryptChacha20poly1305(key, nonce, ciphertext []byte) (text string, err error) {
	// create a new ChaCha20-Poly1305 AEAD using the given 256-bit key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
		return
	}

	// decrypt the data
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = fmt.Errorf("error decrypting data: %v", err)
		return
	}
	text = string(plaintext)

	return
}

// EncryptChacha20poly1305WithNonceAppended encrypts and authenticates the given message with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
// It appends the ciphertext to the nonce [ciphertext = nonce + ciphertext].
func EncryptChacha20poly1305WithNonceAppended(key []byte, text string) (ciphertext []byte, err error) {
	ciphertext, nonce, err := EncryptChacha20poly1305(key, text)
	if err != nil {
		return
	}
	ciphertext = append(nonce, ciphertext...)
	return
}

// DecryptChacha20poly1305WithNonceAppended decrypts and authenticates the given message with
// ChaCha20-Poly1305 AEAD using the given 256-bit key and 96-bit nonce.
// It expects the ciphertext along with the nonce [ciphertext = nonce + ciphertext].
func DecryptChacha20poly1305WithNonceAppended(key, ciphertext []byte) (text string, err error) {
	nonceSize := chacha20poly1305.NonceSize
	if len(ciphertext) < nonceSize {
		err = errors.New("ciphertext is too short")
		return
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	text, err = DecryptChacha20poly1305(key, nonce, ciphertext)
	return
}

// EncryptXChacha20poly1305 encrypts and authenticates the given message with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
func EncryptXChacha20poly1305(key []byte, text string) (ciphertext []byte, nonce []byte, err error) {
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

	// data to be encrypted
	data := []byte(text)

	// encrypt the data
	ciphertext = aead.Seal(nil, nonce, data, nil)

	return
}

// DecryptXChacha20poly1305 decrypts and authenticates the given message with
// XChaCha20-Poly1305 AEAD using the given 256-bit key and 192-bit nonce.
func DecryptXChacha20poly1305(key, nonce, ciphertext []byte) (text string, err error) {
	// create a new XChaCha20-Poly1305 AEAD using the given 256-bit key
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		err = fmt.Errorf("error creating AEAD: %v", err)
		return
	}

	// decrypt the data
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = fmt.Errorf("error decrypting data: %v", err)
		return
	}
	text = string(plaintext)

	return
}
