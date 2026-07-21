package crypt

import "testing"

func TestNewEncoder(t *testing.T) {
	pubPEM, privPEM := testRSAKeyPair(t)

	t.Run("valid", func(t *testing.T) {
		e := NewEncoder(pubPEM)
		if e.Err != nil {
			t.Fatalf("unexpected Err: %v", e.Err)
		}
		if e.PubKeyBlock == nil {
			t.Fatal("PubKeyBlock is nil for a valid public key")
		}
		if e.PubKeyBlock.Type != "PUBLIC KEY" {
			t.Errorf("PubKeyBlock.Type = %q, want %q", e.PubKeyBlock.Type, "PUBLIC KEY")
		}
		if e.HashAlg != SHA256 {
			t.Errorf("default HashAlg = %v, want SHA256 (zero value)", e.HashAlg)
		}
	})

	t.Run("garbagePEM", func(t *testing.T) {
		if e := NewEncoder("not a pem block"); e.Err == nil {
			t.Error("expected Err for undecodable PEM, got nil")
		}
	})

	t.Run("wrongBlockType", func(t *testing.T) {
		// a private-key PEM must be rejected by the public-key encoder
		if e := NewEncoder(privPEM); e.Err == nil {
			t.Error("expected Err when given a PRIVATE KEY block, got nil")
		}
	})
}
