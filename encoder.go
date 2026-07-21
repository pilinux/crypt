package crypt

import (
	"encoding/pem"
	"fmt"
)

// HashAlgorithm selects the hash used by RSA-OAEP in
// [Encoder.EncryptRSA] and [Decoder.DecryptRSA].
type HashAlgorithm int

const (
	// SHA256 selects SHA-256. It is the default (the zero value).
	SHA256 HashAlgorithm = iota
	// SHA512 selects SHA-512.
	SHA512
)

// Encoder holds a PEM-decoded RSA public key and is the entry point for
// [Encoder.EncryptRSA] and the Base64 encoding helpers.
//
// Construct one with [NewEncoder] and check Err before use: the constructor
// reports a bad PEM input on the Err field instead of returning an error.
type Encoder struct {
	// PubKeyBlock is the decoded PEM block of the public key.
	PubKeyBlock *pem.Block
	// HashAlg is the hash used by EncryptRSA; the zero value is SHA256.
	HashAlg HashAlgorithm
	// Err is non-nil when NewEncoder could not decode the public key PEM.
	Err error
}

// NewEncoder decodes a PEM-encoded RSA public key (a "PUBLIC KEY" block) and
// returns an Encoder for it. It never returns nil; if the input is not a valid
// public-key PEM block, the returned Encoder has its Err field set, so callers
// should check Err before calling EncryptRSA.
func NewEncoder(publicKeyPEM string) *Encoder {
	var err error
	pubKeyBlock, _ := pem.Decode([]byte(publicKeyPEM))
	if pubKeyBlock == nil || pubKeyBlock.Type != "PUBLIC KEY" {
		err = fmt.Errorf("failed to decode public key")
	}

	return &Encoder{
		PubKeyBlock: pubKeyBlock,
		Err:         err,
	}
}
