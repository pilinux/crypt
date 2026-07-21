package crypt

import (
	"encoding/pem"
	"fmt"
)

// Decoder holds a PEM-decoded RSA private key and is the entry point for
// [Decoder.DecryptRSA] and the Base64 decoding helpers.
//
// Construct one with [NewDecoder] and check Err before use: the constructor
// reports a bad PEM input on the Err field instead of returning an error.
type Decoder struct {
	// PriKeyBlock is the decoded PEM block of the private key.
	PriKeyBlock *pem.Block
	// HashAlg is the hash used by DecryptRSA; the zero value is SHA256.
	HashAlg HashAlgorithm
	// Err is non-nil when NewDecoder could not decode the private key PEM.
	Err error
}

// NewDecoder decodes a PEM-encoded RSA private key (a PKCS#8 "PRIVATE KEY"
// block) and returns a Decoder for it. It never returns nil; if the input is
// not a valid private-key PEM block, the returned Decoder has its Err field
// set, so callers should check Err before calling DecryptRSA.
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
