package crypt

import (
	"encoding/pem"
	"fmt"
)

// HashAlgorithm enum for selecting the hash algorithm.
type HashAlgorithm int

const (
	// SHA256 selects SHA-256 as the hash algorithm.
	SHA256 HashAlgorithm = iota
	// SHA512 selects SHA-512 as the hash algorithm.
	SHA512
)

// Encoder - PEM-encoded block of data
type Encoder struct {
	PubKeyBlock *pem.Block
	HashAlg     HashAlgorithm
	Err         error
}

// NewEncoder takes a PEM-encoded public key string
// as input and attempts to decode it.
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
