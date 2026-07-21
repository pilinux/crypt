package crypt

import "encoding/base64"

// ToBase64Std encodes binary data to a Base64 string using the standard
// alphabet (RFC 4648).
func (e *Encoder) ToBase64Std(text []byte) string {
	return base64.StdEncoding.EncodeToString(text)
}

// ToBase64RawStd encodes binary data to a Base64 string using the standard
// alphabet without padding (RFC 4648 section 3.2): the same as ToBase64Std but
// with the trailing '=' characters omitted.
func (e *Encoder) ToBase64RawStd(text []byte) string {
	return base64.RawStdEncoding.EncodeToString(text)
}

// ToBase64URL encodes binary data to a Base64 string using the URL- and
// filename-safe alphabet (RFC 4648 section 5).
func (e *Encoder) ToBase64URL(text []byte) string {
	return base64.URLEncoding.EncodeToString(text)
}

// ToBase64RawURL encodes binary data to a Base64 string using the URL- and
// filename-safe alphabet without padding (RFC 4648 section 5).
func (e *Encoder) ToBase64RawURL(text []byte) string {
	return base64.RawURLEncoding.EncodeToString(text)
}

// FromBase64Std decodes a Base64 string produced with the standard alphabet
// (RFC 4648) back into binary data.
func (d *Decoder) FromBase64Std(text string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(text)
}

// FromBase64RawStd decodes an unpadded Base64 string produced with the standard
// alphabet (RFC 4648 section 3.2) back into binary data.
func (d *Decoder) FromBase64RawStd(text string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(text)
}

// FromBase64URL decodes a Base64 string produced with the URL- and
// filename-safe alphabet (RFC 4648 section 5) back into binary data.
func (d *Decoder) FromBase64URL(text string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(text)
}

// FromBase64RawURL decodes an unpadded Base64 string produced with the URL- and
// filename-safe alphabet (RFC 4648 section 5) back into binary data.
func (d *Decoder) FromBase64RawURL(text string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(text)
}
