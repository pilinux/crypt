package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// EncryptRSA encrypts the given message with RSA-OAEP and using SHA-256 (default) or SHA-512.
func (e *Encoder) EncryptRSA(text string) (ciphertext []byte, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(e.PubKeyBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("error parsing public key: %v", err)
		return
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("failed to cast public key to RSA public key")
		return
	}

	var hashAlg crypto.Hash
	switch e.HashAlg {
	case SHA512:
		hashAlg = crypto.SHA512
	default:
		hashAlg = crypto.SHA256
	}

	// encrypt the data using RSA-OAEP
	ciphertext, err = rsa.EncryptOAEP(
		hashAlg.New(),
		rand.Reader,
		rsaPubKey,
		[]byte(text),
		nil,
	)
	if err != nil {
		err = fmt.Errorf("error encrypting data: %v", err)
		return
	}

	return
}

// DecryptRSA decrypts the given message with RSA-OAEP and using SHA-256 (default) or SHA-512.
func (d *Decoder) DecryptRSA(ciphertext []byte) (text string, err error) {
	priKey, err := x509.ParsePKCS8PrivateKey(d.PriKeyBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("error parsing private key: %v", err)
		return
	}

	rsaPriKey, ok := priKey.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("failed to cast private key to RSA private key")
		return
	}

	var hashAlg crypto.Hash
	switch d.HashAlg {
	case SHA512:
		hashAlg = crypto.SHA512
	default:
		hashAlg = crypto.SHA256
	}

	// decrypt the data using RSA-OAEP
	plaintext, err := rsa.DecryptOAEP(
		hashAlg.New(),
		rand.Reader,
		rsaPriKey,
		ciphertext,
		nil,
	)
	if err != nil {
		err = fmt.Errorf("error decrypting data: %v", err)
		return
	}
	text = string(plaintext)

	return
}
