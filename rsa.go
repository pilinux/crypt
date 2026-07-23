package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // link SHA-256 so crypto.SHA256.New() never panics
	_ "crypto/sha512" // link SHA-512 so crypto.SHA512.New() never panics
	"crypto/x509"
	"fmt"
)

// hash resolves the HashAlgorithm to a crypto.Hash for RSA-OAEP. It rejects
// unknown values instead of silently defaulting to SHA-256, and verifies the
// implementation is linked into the binary so a later New() call cannot panic.
func (h HashAlgorithm) hash() (crypto.Hash, error) {
	var alg crypto.Hash
	switch h {
	case SHA256:
		alg = crypto.SHA256
	case SHA512:
		alg = crypto.SHA512
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %d", int(h))
	}
	if !alg.Available() {
		return 0, fmt.Errorf("hash algorithm %v is not linked into the binary", alg)
	}
	return alg, nil
}

// EncryptByteRSA encrypts the given message (bytes) with RSA-OAEP and using SHA-256 (default) or SHA-512.
func (e *Encoder) EncryptByteRSA(input []byte) (ciphertext []byte, err error) {
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

	hashAlg, err := e.HashAlg.hash()
	if err != nil {
		return
	}

	// encrypt the data using RSA-OAEP
	ciphertext, err = rsa.EncryptOAEP(
		hashAlg.New(),
		rand.Reader,
		rsaPubKey,
		input,
		nil,
	)
	if err != nil {
		err = fmt.Errorf("error encrypting data: %v", err)
		return
	}

	return
}

// EncryptRSA encrypts the given message (string) with RSA-OAEP and using SHA-256 (default) or SHA-512.
func (e *Encoder) EncryptRSA(text string) (ciphertext []byte, err error) {
	return e.EncryptByteRSA([]byte(text))
}

// DecryptByteRSA decrypts the given message with RSA-OAEP and using SHA-256 (default) or SHA-512.
func (d *Decoder) DecryptByteRSA(ciphertext []byte) (plaintext []byte, err error) {
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

	hashAlg, err := d.HashAlg.hash()
	if err != nil {
		return
	}

	// decrypt the data using RSA-OAEP; DecryptOAEP ignores the random
	// argument (it is legacy), so nil documents that intent.
	plaintext, err = rsa.DecryptOAEP(
		hashAlg.New(),
		nil,
		rsaPriKey,
		ciphertext,
		nil,
	)
	if err != nil {
		err = fmt.Errorf("error decrypting data: %v", err)
		return
	}

	return
}

// DecryptRSA decrypts the given message with RSA-OAEP and using SHA-256 (default) or SHA-512.
func (d *Decoder) DecryptRSA(ciphertext []byte) (text string, err error) {
	plaintext, err := d.DecryptByteRSA(ciphertext)
	if err != nil {
		return
	}

	text = string(plaintext)
	return
}
