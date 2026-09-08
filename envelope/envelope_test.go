package envelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{name: "zero", n: 0},
		{name: "one", n: 1},
		{name: "thirtyTwo", n: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := randomBytes(tt.n)
			if err != nil {
				t.Fatalf("randomBytes(%d) error: %v", tt.n, err)
			}
			if len(b) != tt.n {
				t.Errorf("randomBytes(%d) len = %d, want %d", tt.n, len(b), tt.n)
			}
		})
	}

	// two non-empty draws must not be identical
	a, _ := randomBytes(16)
	b, _ := randomBytes(16)
	if bytes.Equal(a, b) {
		t.Error("two random draws are identical")
	}
}

func TestBuildHeaderUnpackEnvelope(t *testing.T) {
	t.Run("roundTrip", func(t *testing.T) {
		salt := bytes.Repeat([]byte{0xAB}, SaltSize)
		// ciphertext must be at least NonceSize+TagSize to be considered valid
		ciphertext := bytes.Repeat([]byte{0xCD}, NonceSize+TagSize+5)

		header, err := buildHeader(salt)
		if err != nil {
			t.Fatalf("buildHeader error: %v", err)
		}
		if header[0] != envelopeVersion || int(header[1]) != SaltSize {
			t.Errorf("header = %x, want version 0x%02x and saltLen %d", header[:2], envelopeVersion, SaltSize)
		}

		blob := append(append([]byte{}, header...), ciphertext...)

		gotHeader, gotSalt, gotCipher, err := unpackEnvelope(blob)
		if err != nil {
			t.Fatalf("unpackEnvelope error: %v", err)
		}
		if !bytes.Equal(gotHeader, header) {
			t.Error("header round-trip mismatch")
		}
		if !bytes.Equal(gotSalt, salt) {
			t.Error("salt round-trip mismatch")
		}
		if !bytes.Equal(gotCipher, ciphertext) {
			t.Error("ciphertext round-trip mismatch")
		}
	})

	t.Run("rejectBadSaltSizes", func(t *testing.T) {
		if _, err := buildHeader(nil); err != ErrInvalidSaltSize {
			t.Errorf("empty salt: err = %v, want ErrInvalidSaltSize", err)
		}
		if _, err := buildHeader(make([]byte, 256)); err != ErrInvalidSaltSize {
			t.Errorf("oversized salt: err = %v, want ErrInvalidSaltSize", err)
		}
	})

	t.Run("rejectBadBlobs", func(t *testing.T) {
		cases := map[string][]byte{
			"tooShort":       {envelopeVersion},
			"wrongVersion":   append([]byte{0x02, byte(SaltSize)}, bytes.Repeat([]byte{0}, SaltSize+NonceSize+TagSize)...),
			"unknownVersion": append([]byte{0x7F, byte(SaltSize)}, bytes.Repeat([]byte{0}, SaltSize+NonceSize+TagSize)...),
			"zeroSaltLen":    {envelopeVersion, 0x00},
			"truncated":      {envelopeVersion, byte(SaltSize), 0x00},
		}
		for name, blob := range cases {
			if _, _, _, err := unpackEnvelope(blob); err != ErrBadEnvelope {
				t.Errorf("%s: err = %v, want ErrBadEnvelope", name, err)
			}
		}
	})

	t.Run("authDataConcatenation", func(t *testing.T) {
		header := []byte{envelopeVersion, 0x02, 0xAA, 0xBB}
		if got := authData(header, nil); !bytes.Equal(got, header) {
			t.Errorf("authData(header, nil) = %x, want header alone", got)
		}
		want := append(append([]byte{}, header...), 'i', 'd')
		if got := authData(header, []byte("id")); !bytes.Equal(got, want) {
			t.Errorf("authData(header, id) = %x, want %x", got, want)
		}
	})
}

func TestSchemeLabels(t *testing.T) {
	t.Run("differentKEKLabelDifferentKEK", func(t *testing.T) {
		a, _ := New(Config{KEKLabel: "app-a:kek"}).DeriveKEK(validSecret)
		b, _ := New(Config{KEKLabel: "app-b:kek"}).DeriveKEK(validSecret)
		if bytes.Equal(a, b) {
			t.Error("different KEK labels produced the same KEK")
		}
	})

	t.Run("differentSubKeyLabelDifferentSubKey", func(t *testing.T) {
		mk, _ := GenerateMasterKey()
		salt, _ := GenerateSalt()
		a, _ := New(Config{SubKeyLabel: "app-a:sub"}).DeriveSubKey(mk, salt)
		b, _ := New(Config{SubKeyLabel: "app-b:sub"}).DeriveSubKey(mk, salt)
		if bytes.Equal(a, b) {
			t.Error("different sub-key labels produced the same sub-key")
		}
	})

	t.Run("emptyConfigUsesDefaults", func(t *testing.T) {
		a, _ := New(Config{}).DeriveKEK(validSecret)
		b, _ := New(Config{KEKLabel: DefaultKEKLabel, SubKeyLabel: DefaultSubKeyLabel}).DeriveKEK(validSecret)
		if !bytes.Equal(a, b) {
			t.Error("empty config did not fall back to default labels")
		}
	})
}

// TestUnpackEnvelopeRejectsForeignSaltLen pins that a salt length the format
// never writes is a malformed envelope. It used to pass the parser and fail two
// calls later as ErrInvalidSaltSize, which names a caller's argument rather
// than untrusted wire data, so a handler mapping errors to status codes could
// not tell a bad request from its own bug.
func TestUnpackEnvelopeRejectsForeignSaltLen(t *testing.T) {
	for _, saltLen := range []int{1, 8, 15, 17, 32, 255} {
		blob := make([]byte, 2+saltLen+NonceSize+TagSize)
		blob[0] = envelopeVersion
		blob[1] = byte(saltLen)

		if _, _, _, err := unpackEnvelope(blob); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("saltLen %d: err = %v, want ErrBadEnvelope", saltLen, err)
		}
		if _, err := Default().OpenBytes(make([]byte, KeySize), blob); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("saltLen %d via OpenBytes: err = %v, want ErrBadEnvelope", saltLen, err)
		}
	}
}

// TestErrSecretTooShortCountsBytes pins the message against the rule it
// describes: len(secret) is bytes, so the text may not promise characters.
func TestErrSecretTooShortCountsBytes(t *testing.T) {
	if strings.Contains(ErrSecretTooShort.Error(), "characters") {
		t.Error("the message says characters, but the check counts bytes")
	}
	// 16 two-byte runes: 16 characters, 32 bytes, and accepted
	if _, err := Default().DeriveKEK(strings.Repeat("é", 16)); err != nil {
		t.Errorf("32 bytes of multi-byte runes: err = %v, want nil", err)
	}
	if _, err := Default().DeriveKEK(strings.Repeat("a", MinSecretLength-1)); !errors.Is(err, ErrSecretTooShort) {
		t.Errorf("31 bytes: err = %v, want ErrSecretTooShort", err)
	}
}
