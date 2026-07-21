package envelope

import (
	"bytes"
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

func TestPackUnpackEnvelope(t *testing.T) {
	t.Run("roundTrip", func(t *testing.T) {
		salt := bytes.Repeat([]byte{0xAB}, SaltSize)
		// ciphertext must be at least NonceSize+TagSize to be considered valid
		ciphertext := bytes.Repeat([]byte{0xCD}, NonceSize+TagSize+5)

		blob, err := packEnvelope(salt, ciphertext)
		if err != nil {
			t.Fatalf("packEnvelope error: %v", err)
		}

		gotSalt, gotCipher, err := unpackEnvelope(blob)
		if err != nil {
			t.Fatalf("unpackEnvelope error: %v", err)
		}
		if !bytes.Equal(gotSalt, salt) {
			t.Error("salt round-trip mismatch")
		}
		if !bytes.Equal(gotCipher, ciphertext) {
			t.Error("ciphertext round-trip mismatch")
		}
	})

	t.Run("rejectEmptySalt", func(t *testing.T) {
		if _, err := packEnvelope(nil, []byte("x")); err != ErrInvalidSaltSize {
			t.Errorf("err = %v, want ErrInvalidSaltSize", err)
		}
	})

	t.Run("rejectBadBlobs", func(t *testing.T) {
		cases := map[string][]byte{
			"tooShort":     {0x01},
			"wrongVersion": append([]byte{0x02, byte(SaltSize)}, bytes.Repeat([]byte{0}, SaltSize+NonceSize+TagSize)...),
			"zeroSaltLen":  {envelopeVersion, 0x00},
			"truncated":    {envelopeVersion, byte(SaltSize), 0x00},
		}
		for name, blob := range cases {
			if _, _, err := unpackEnvelope(blob); err != ErrBadEnvelope {
				t.Errorf("%s: err = %v, want ErrBadEnvelope", name, err)
			}
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
