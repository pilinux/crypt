package crypt

import "testing"

func TestNewDecoder(t *testing.T) {
	pubPEM, privPEM := testRSAKeyPair(t)

	t.Run("valid", func(t *testing.T) {
		d := NewDecoder(privPEM)
		if d.Err != nil {
			t.Fatalf("unexpected Err: %v", d.Err)
		}
		if d.PriKeyBlock == nil {
			t.Fatal("PriKeyBlock is nil for a valid private key")
		}
		if d.PriKeyBlock.Type != "PRIVATE KEY" {
			t.Errorf("PriKeyBlock.Type = %q, want %q", d.PriKeyBlock.Type, "PRIVATE KEY")
		}
		if d.HashAlg != SHA256 {
			t.Errorf("default HashAlg = %v, want SHA256 (zero value)", d.HashAlg)
		}
	})

	t.Run("garbagePEM", func(t *testing.T) {
		if d := NewDecoder("not a pem block"); d.Err == nil {
			t.Error("expected Err for undecodable PEM, got nil")
		}
	})

	t.Run("wrongBlockType", func(t *testing.T) {
		// a public-key PEM must be rejected by the private-key decoder
		if d := NewDecoder(pubPEM); d.Err == nil {
			t.Error("expected Err when given a PUBLIC KEY block, got nil")
		}
	})
}
