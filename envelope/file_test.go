package envelope

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeTempFile writes content to a new file in t.TempDir and returns its path.
func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, filePerm); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	return path
}

func TestSealOpenFile(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	plaintext := randomData(t, 3*testChunkSize+123)

	srcPath := writeTempFile(t, "plain.bin", plaintext)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "plain.bin.enc")
	openedPath := filepath.Join(dir, "plain.out")
	aad := []byte("plain.bin")

	n, err := s.SealFileAAD(masterKey, sealedPath, srcPath, aad)
	if err != nil {
		t.Fatalf("SealFileAAD error: %v", err)
	}
	if n != int64(len(plaintext)) {
		t.Errorf("sealed %d bytes, want %d", n, len(plaintext))
	}

	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(sealed) != sealedSize(len(plaintext)) {
		t.Errorf("sealed file len = %d, want %d", len(sealed), sealedSize(len(plaintext)))
	}

	n, err = s.OpenFileAAD(masterKey, openedPath, sealedPath, aad)
	if err != nil {
		t.Fatalf("OpenFileAAD error: %v", err)
	}
	if n != int64(len(plaintext)) {
		t.Errorf("opened %d bytes, want %d", n, len(plaintext))
	}

	opened, err := os.ReadFile(openedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Error("round-trip mismatch")
	}
	if Sha256Hex(opened) != Sha256Hex(plaintext) {
		t.Error("digest mismatch")
	}
}

func TestSealOpenFileNoAAD(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	plaintext := []byte("a short file")

	srcPath := writeTempFile(t, "note.txt", plaintext)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "note.enc")
	openedPath := filepath.Join(dir, "note.out")

	if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}
	if _, err := s.OpenFile(masterKey, openedPath, sealedPath); err != nil {
		t.Fatalf("OpenFile error: %v", err)
	}

	opened, err := os.ReadFile(openedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Error("round-trip mismatch")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(sealedPath)
		if err != nil {
			t.Fatalf("Stat error: %v", err)
		}
		if info.Mode().Perm() != filePerm {
			t.Errorf("sealed file mode = %v, want %v", info.Mode().Perm(), filePerm)
		}
	}
}

func TestSealFileRefusesExistingDestination(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	plaintext := []byte("do not destroy me")
	srcPath := writeTempFile(t, "source.bin", plaintext)

	// the classic mix-up: destination and source are the same file
	if _, err := s.SealFile(masterKey, srcPath, srcPath); err == nil {
		t.Error("SealFile overwrote an existing destination, want failure")
	}

	kept, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if !bytes.Equal(kept, plaintext) {
		t.Error("source file was modified")
	}
}

func TestSealFileMissingSource(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	dir := t.TempDir()

	if _, err := s.SealFile(masterKey, filepath.Join(dir, "out.enc"), filepath.Join(dir, "nope.bin")); err == nil {
		t.Error("SealFile with a missing source succeeded, want failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "out.enc")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a destination file was created for a missing source")
	}
}

func TestOpenFileCorruptRemovesOutput(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	srcPath := writeTempFile(t, "big.bin", randomData(t, 4*testChunkSize))
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "big.enc")
	openedPath := filepath.Join(dir, "big.out")

	if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}

	// corrupt the last chunk, so the failure only shows up part-way through
	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	sealed[len(sealed)-1] ^= 0xFF
	if err := os.WriteFile(sealedPath, sealed, filePerm); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	if _, err := s.OpenFile(masterKey, openedPath, sealedPath); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("err = %v, want ErrStreamAuth", err)
	}
	if _, err := os.Stat(openedPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("partial output was left behind")
	}
}
