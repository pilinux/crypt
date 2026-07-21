package envelope

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256Hex returns the lowercase hex-encoded SHA-256 digest of data. It is
// handy for recording an integrity fingerprint of a plaintext (for example a
// file) before it is encrypted, so a later decryption can be verified end to
// end.
func Sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RandomHex returns a random identifier made of n bytes, hex-encoded (so the
// resulting string is 2*n characters long). It is handy for minting
// unpredictable IDs that double as safe on-disk filenames.
func RandomHex(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
