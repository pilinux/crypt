package envelope

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// paddedTestSize is a payload whose Padmé bucket is 2048 bytes wide, so the
// padding spans more than one testChunkSize chunk. That is what makes the
// padding-only truncation case reachable.
const paddedTestSize = 65546

func TestPaddedSize(t *testing.T) {
	tests := []struct {
		name string
		n    int64
		want int64
	}{
		{name: "empty", n: 0, want: 10},
		{name: "tiny", n: 1, want: 10},
		{name: "small", n: 1000, want: 1024},
		{name: "medium", n: 96037, want: 96256},
		{name: "bucket neighbour", n: 96200, want: 96256},
		{name: "next bucket", n: 100000, want: 100352},
		{name: "negative", n: -1, want: 0},
		{name: "overflows the frame", n: math.MaxInt64 - 1, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PaddedSize(tt.n); got != tt.want {
				t.Errorf("PaddedSize(%d) = %d, want %d", tt.n, got, tt.want)
			}
		})
	}
}

func TestPaddedSizeOverhead(t *testing.T) {
	for n := int64(1); n < 1<<24; n = n*3/2 + 1 {
		padded := PaddedSize(n)
		if padded < n+paddingFrameSize {
			t.Fatalf("PaddedSize(%d) = %d, shorter than the framed payload", n, padded)
		}
		// Padmé caps the overhead at roughly 12%; allow the frame plus a
		// little slack for the tiny lengths where the frame dominates.
		if limit := (n+paddingFrameSize)*112/100 + 8; padded > limit {
			t.Errorf("PaddedSize(%d) = %d, over the 12%% cap of %d", n, padded, limit)
		}
	}
}

func TestPaddedSizeIsMonotonic(t *testing.T) {
	prev := PaddedSize(0)
	for n := int64(1); n < 1<<17; n++ {
		got := PaddedSize(n)
		if got < prev {
			t.Fatalf("PaddedSize(%d) = %d, below PaddedSize(%d) = %d", n, got, n-1, prev)
		}
		prev = got
	}
}

func TestSealOpenPaddedFile(t *testing.T) {
	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			s := streamScheme()
			masterKey := newMasterKey(t)
			payload := randomData(t, tt.n)

			srcPath := writeTempFile(t, "plain.bin", payload)
			dir := filepath.Dir(srcPath)
			sealedPath := filepath.Join(dir, "plain.bin.enc")
			openedPath := filepath.Join(dir, "plain.out")

			n, err := s.SealPaddedFile(masterKey, sealedPath, srcPath)
			if err != nil {
				t.Fatalf("SealPaddedFile error: %v", err)
			}
			if n != int64(len(payload)) {
				t.Errorf("sealed %d payload bytes, want %d", n, len(payload))
			}

			padded := PaddedSize(int64(len(payload)))
			info, err := os.Stat(sealedPath)
			if err != nil {
				t.Fatalf("Stat error: %v", err)
			}
			if want := int64(sealedSize(int(padded))); info.Size() != want {
				t.Errorf("sealed file len = %d, want %d", info.Size(), want)
			}

			n, err = s.OpenPaddedFile(masterKey, openedPath, sealedPath)
			if err != nil {
				t.Fatalf("OpenPaddedFile error: %v", err)
			}
			if n != int64(len(payload)) {
				t.Errorf("opened %d bytes, want %d", n, len(payload))
			}

			opened, err := os.ReadFile(openedPath)
			if err != nil {
				t.Fatalf("ReadFile error: %v", err)
			}
			if !bytes.Equal(opened, payload) {
				t.Error("recovered payload differs from the original")
			}
		})
	}
}

func TestSealPaddedFileAAD(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, 2*testChunkSize+7)
	aad := []byte("plain.bin")

	srcPath := writeTempFile(t, "plain.bin", payload)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "plain.bin.enc")

	if _, err := s.SealPaddedFileAAD(masterKey, sealedPath, srcPath, aad); err != nil {
		t.Fatalf("SealPaddedFileAAD error: %v", err)
	}

	if _, err := s.OpenPaddedFileAAD(masterKey, filepath.Join(dir, "wrong.out"), sealedPath, []byte("other.bin")); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("open with the wrong aad: err = %v, want ErrStreamAuth", err)
	}
	if _, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "none.out"), sealedPath); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("open with no aad: err = %v, want ErrStreamAuth", err)
	}

	openedPath := filepath.Join(dir, "plain.out")
	if _, err := s.OpenPaddedFileAAD(masterKey, openedPath, sealedPath, aad); err != nil {
		t.Fatalf("OpenPaddedFileAAD error: %v", err)
	}
	opened, err := os.ReadFile(openedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Error("recovered payload differs from the original")
	}
}

// TestPaddedFileHidesLength is the point of the whole file: payloads of
// different sizes that share a bucket must be the same size on disk.
func TestPaddedFileHidesLength(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	dir := t.TempDir()

	sizes := []int{94500, 96037, 96200}
	var first int64
	for i, n := range sizes {
		srcPath := filepath.Join(dir, "plain.bin")
		if err := os.WriteFile(srcPath, randomData(t, n), filePerm); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}
		sealedPath := filepath.Join(dir, "plain.bin.enc")
		if _, err := s.SealPaddedFile(masterKey, sealedPath, srcPath); err != nil {
			t.Fatalf("SealPaddedFile error: %v", err)
		}
		info, err := os.Stat(sealedPath)
		if err != nil {
			t.Fatalf("Stat error: %v", err)
		}
		if i == 0 {
			first = info.Size()
		} else if info.Size() != first {
			t.Errorf("payload %d sealed to %d bytes, want %d like its bucket peers", n, info.Size(), first)
		}
		if err := os.Remove(sealedPath); err != nil {
			t.Fatalf("Remove error: %v", err)
		}
	}

	// the unpadded helper leaks the difference the padded one hides
	srcPath := writeTempFile(t, "plain.bin", randomData(t, sizes[0]))
	plainSealed := filepath.Join(filepath.Dir(srcPath), "plain.bin.enc")
	if _, err := s.SealFile(masterKey, plainSealed, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}
	info, err := os.Stat(plainSealed)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	if info.Size() == first {
		t.Error("unpadded seal produced the padded size, expected it to reveal the shorter payload")
	}
}

// TestOpenPaddedFileDetectsPaddingTruncation covers the reason the reader
// drains the stream: chunks holding nothing but padding must still be
// authenticated.
func TestOpenPaddedFileDetectsPaddingTruncation(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)

	pad := PaddedSize(int64(len(payload))) - paddingFrameSize - int64(len(payload))
	if pad < testChunkSize {
		t.Fatalf("padding is %d bytes, need at least one full chunk (%d) for this test", pad, testChunkSize)
	}

	srcPath := writeTempFile(t, "plain.bin", payload)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "plain.bin.enc")
	if _, err := s.SealPaddedFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealPaddedFile error: %v", err)
	}

	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	cutPath := filepath.Join(dir, "cut.enc")
	if err := os.WriteFile(cutPath, sealed[:len(sealed)-(testChunkSize+TagSize)], filePerm); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	openedPath := filepath.Join(dir, "cut.out")
	if _, err := s.OpenPaddedFile(masterKey, openedPath, cutPath); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("truncated padding: err = %v, want ErrStreamAuth", err)
	}
	if _, err := os.Stat(openedPath); !os.IsNotExist(err) {
		t.Error("partial output was not removed")
	}
}

func TestOpenPaddedFileRejectsUnpadded(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	// a payload that cannot be mistaken for a frame: the first byte differs
	// from paddingVersion.
	payload := bytes.Repeat([]byte{0xAA}, 3*testChunkSize)

	srcPath := writeTempFile(t, "plain.bin", payload)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "plain.bin.enc")
	if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}

	if _, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "plain.out"), sealedPath); !errors.Is(err, ErrNotPadded) {
		t.Errorf("open unpadded stream: err = %v, want ErrNotPadded", err)
	}
}

func TestOpenPaddedFileRejectsShortPayload(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// a frame promising more payload than the stream carries
	var frame [paddingFrameSize]byte
	frame[0] = paddingVersion
	frame[8] = 0xFF
	srcPath := writeTempFile(t, "frame.bin", frame[:])
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "frame.enc")
	if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}

	if _, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "frame.out"), sealedPath); !errors.Is(err, ErrNotPadded) {
		t.Errorf("open truncated frame: err = %v, want ErrNotPadded", err)
	}
}

func TestOpenPaddedFileRejectsEmptyPlaintext(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	srcPath := writeTempFile(t, "empty.bin", nil)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "empty.enc")
	if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}

	if _, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "empty.out"), sealedPath); !errors.Is(err, ErrNotPadded) {
		t.Errorf("open empty stream: err = %v, want ErrNotPadded", err)
	}
}

func TestSealPaddedFileRejectsIrregularSource(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	dir := t.TempDir()

	if _, err := s.SealPaddedFile(masterKey, filepath.Join(dir, "out.enc"), dir); !errors.Is(err, ErrSourceSize) {
		t.Errorf("seal a directory: err = %v, want ErrSourceSize", err)
	}
}

func TestSealPaddedFileRejectsExistingDestination(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	srcPath := writeTempFile(t, "plain.bin", randomData(t, 512))
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "taken.enc")
	if err := os.WriteFile(sealedPath, []byte("do not overwrite me"), filePerm); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	if _, err := s.SealPaddedFile(masterKey, sealedPath, srcPath); err == nil {
		t.Error("SealPaddedFile overwrote an existing destination")
	}
	kept, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if string(kept) != "do not overwrite me" {
		t.Error("existing destination was modified")
	}
}

func TestSealPaddedStreamRejectsSizeMismatch(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, 4096)

	var out bytes.Buffer
	// claim a larger payload than the reader will deliver
	_, err := s.sealPaddedStream(masterKey, &out, bytes.NewReader(payload), int64(len(payload))+1024, nil)
	if !errors.Is(err, ErrSourceSize) {
		t.Errorf("short source: err = %v, want ErrSourceSize", err)
	}
}

func TestPaddedRoundTripThroughZeroPayload(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	srcPath := writeTempFile(t, "empty.bin", nil)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "empty.enc")
	openedPath := filepath.Join(dir, "empty.out")

	if _, err := s.SealPaddedFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealPaddedFile error: %v", err)
	}
	n, err := s.OpenPaddedFile(masterKey, openedPath, sealedPath)
	if err != nil {
		t.Fatalf("OpenPaddedFile error: %v", err)
	}
	if n != 0 {
		t.Errorf("opened %d bytes, want 0", n)
	}
	opened, err := os.ReadFile(openedPath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(opened) != 0 {
		t.Errorf("recovered %d bytes, want an empty file", len(opened))
	}
}
