package envelope

import (
	"encoding/hex"
	"testing"
)

func TestSha256Hex(t *testing.T) {
	t.Run("knownVector", func(t *testing.T) {
		// SHA-256 of the empty input is a well-known constant.
		const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if got := Sha256Hex([]byte{}); got != emptyDigest {
			t.Errorf("Sha256Hex(empty) = %s, want %s", got, emptyDigest)
		}
	})

	t.Run("stableAndDistinct", func(t *testing.T) {
		a := Sha256Hex([]byte("data"))
		b := Sha256Hex([]byte("data"))
		if a != b {
			t.Error("Sha256Hex is not deterministic")
		}
		if a == Sha256Hex([]byte("other")) {
			t.Error("different inputs produced the same digest")
		}
		if len(a) != 64 {
			t.Errorf("digest length = %d, want 64 hex chars", len(a))
		}
	})
}

func TestRandomHex(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantLen int
	}{
		{name: "eightBytes", n: 8, wantLen: 16},
		{name: "sixteenBytes", n: 16, wantLen: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := RandomHex(tt.n)
			if err != nil {
				t.Fatalf("RandomHex error: %v", err)
			}
			if len(id) != tt.wantLen {
				t.Errorf("RandomHex(%d) len = %d, want %d", tt.n, len(id), tt.wantLen)
			}
			if _, err := hex.DecodeString(id); err != nil {
				t.Errorf("RandomHex output is not valid hex: %v", err)
			}
		})
	}

	t.Run("unique", func(t *testing.T) {
		a, _ := RandomHex(16)
		b, _ := RandomHex(16)
		if a == b {
			t.Error("two RandomHex values are identical")
		}
	})
}
