package crypt

import "encoding/base64"

// ToBase64Std - encode the binary data into a Base64-encoded string
// using the standard Base64 character set.
func (e *Encoder) ToBase64Std(text []byte) string {
	return base64.StdEncoding.EncodeToString(text)
}

// ToBase64RawStd - encode the binary data into a Base64-encoded string
// using the standard raw, unpadded base64 encoding character set, as
// defined in RFC 4648 section 3.2. This is the same as StdEncoding but
// omits the padding characters.
func (e *Encoder) ToBase64RawStd(text []byte) string {
	return base64.RawStdEncoding.EncodeToString(text)
}

// ToBase64URL - encode the binary data into a Base64-encoded string
// using the alternate base64 encoding defined in RFC 4648 suitable for
// URLs and file names.
func (e *Encoder) ToBase64URL(text []byte) string {
	return base64.URLEncoding.EncodeToString(text)
}

// ToBase64RawURL - encode the binary data into a Base64-encoded string
// using the unpadded alternate base64 encoding defined in RFC 4648
// suitable for URLs and file names. It omits the padding characters.
func (e *Encoder) ToBase64RawURL(text []byte) string {
	return base64.RawURLEncoding.EncodeToString(text)
}

// FromBase64Std - decode the Base64-encoded string into binary data
// using the standard Base64 character set.
func (d *Decoder) FromBase64Std(text string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(text)
}

// FromBase64RawStd - decode the Base64-encoded string into binary data
// using the standard raw, unpadded Base64 encoding character set, as
// defined in RFC 4648 section 3.2.
func (d *Decoder) FromBase64RawStd(text string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(text)
}

// FromBase64URL - decode the Base64-encoded string into binary data
// using the alternate base64 encoding defined in RFC 4648.
func (d *Decoder) FromBase64URL(text string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(text)
}

// FromBase64RawURL - decode the Base64-encoded string into binary data
// using the unpadded alternate base64 encoding defined in RFC 4648.
func (d *Decoder) FromBase64RawURL(text string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(text)
}
