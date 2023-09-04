package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptAesGcm encrypts and authenticates the given message with AES in GCM mode
// using the given 128, 192 or 256-bit key.
func EncryptAesGcm(key []byte, text string) (ciphertext []byte, nonce []byte, err error) {
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

// DecryptAesGcm decrypts and authenticates the given message with AES in GCM mode
// using the given 128, 192 or 256-bit key and 96-bit nonce.
func DecryptAesGcm(key, nonce, ciphertext []byte) (text string, err error) {
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

	// decrypt the data
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = fmt.Errorf("error decrypting data: %v", err)
		return
	}
	text = string(plaintext)

	return
}
