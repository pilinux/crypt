package crypt

import (
	"bytes"
	"testing"
)

func TestBase64RoundTrip(t *testing.T) {
	e := &Encoder{}
	d := &Decoder{}
	data := mustBytes(t, 30)

	cases := []struct {
		name string
		enc  func([]byte) string
		dec  func(string) ([]byte, error)
	}{
		{"Std", e.ToBase64Std, d.FromBase64Std},
		{"RawStd", e.ToBase64RawStd, d.FromBase64RawStd},
		{"URL", e.ToBase64URL, d.FromBase64URL},
		{"RawURL", e.ToBase64RawURL, d.FromBase64RawURL},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.dec(c.enc(data))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("round-trip mismatch: got %x, want %x", got, data)
			}
		})
	}
}

func TestBase64KnownVectors(t *testing.T) {
	e := &Encoder{}

	// A single 0xFF byte encodes to a value that needs padding and uses a
	// character that differs between the standard and URL alphabets ('/' vs '_').
	t.Run("paddingAndAlphabet", func(t *testing.T) {
		in := []byte{0xFF}
		checks := []struct {
			name string
			got  string
			want string
		}{
			{"Std", e.ToBase64Std(in), "/w=="},
			{"RawStd", e.ToBase64RawStd(in), "/w"},
			{"URL", e.ToBase64URL(in), "_w=="},
			{"RawURL", e.ToBase64RawURL(in), "_w"},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
			}
		}
	})

	// Three 0xFF bytes need no padding and expose the full alphabet difference.
	t.Run("noPadding", func(t *testing.T) {
		in := []byte{0xFF, 0xFF, 0xFF}
		if got := e.ToBase64Std(in); got != "////" {
			t.Errorf("ToBase64Std = %q, want %q", got, "////")
		}
		if got := e.ToBase64URL(in); got != "____" {
			t.Errorf("ToBase64URL = %q, want %q", got, "____")
		}
	})
}

func TestBase64DecodeError(t *testing.T) {
	d := &Decoder{}
	if _, err := d.FromBase64Std("!!! not base64 !!!"); err == nil {
		t.Error("expected error decoding invalid base64, got nil")
	}
}
