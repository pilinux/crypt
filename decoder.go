package crypt

import (
	"encoding/pem"
	"fmt"
)

// Decoder - PEM-encoded block of data
type Decoder struct {
	PriKeyBlock *pem.Block
	HashAlg     HashAlgorithm
	Err         error
}

// NewDecoder takes a PEM-encoded private key string
// as input and attempts to decode it.
func NewDecoder(privateKeyPEM string) *Decoder {
	var err error
	priKeyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if priKeyBlock == nil || priKeyBlock.Type != "PRIVATE KEY" {
		err = fmt.Errorf("failed to decode private key")
	}

	return &Decoder{
		PriKeyBlock: priKeyBlock,
		Err:         err,
	}
}
