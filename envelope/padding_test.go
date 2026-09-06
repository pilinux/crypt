package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{name: "first length the frame cannot fit", n: math.MaxInt64 - paddingFrameSize + 1, want: 0},
		// the largest paddable length: padme returns it unrounded rather than
		// wrapping the rounding around to something shorter
		{name: "largest paddable", n: math.MaxInt64 - paddingFrameSize, want: math.MaxInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PaddedSize(tt.n); got != tt.want {
				t.Errorf("PaddedSize(%d) = %d, want %d", tt.n, got, tt.want)
			}
		})
	}
}

// TestPadmeShortLengths pins the two short-circuits inside padme. PaddedSize
// cannot reach them, since its shortest input is already the 9-byte frame, so
// calling padme directly is the only way to hold them still.
func TestPadmeShortLengths(t *testing.T) {
	tests := []struct{ l, want int64 }{
		{l: 0, want: 0}, {l: 1, want: 1}, {l: 3, want: 3}, // below the log2 floor
		{l: 4, want: 4}, {l: 5, want: 5}, {l: 7, want: 7}, // bucket narrower than 1: z < 1
		{l: 8, want: 8},  // rounds, but is already on a boundary
		{l: 9, want: 10}, // the first length padme actually moves
	}
	for _, tt := range tests {
		if got := padme(tt.l); got != tt.want {
			t.Errorf("padme(%d) = %d, want %d", tt.l, got, tt.want)
		}
	}
}

// TestPaddedSizeIsMinimal checks PaddedSize against a second reading of the
// Padme rule, derived with floats so a mistake in the bits.Len64 arithmetic
// cannot be reproduced here: the result must sit on a bucket boundary and be
// the first boundary at or above the framed length. An overhead bound alone
// would still pass with the bucket width off by a factor of two, or with the
// result rounded down into the payload.
func TestPaddedSizeIsMinimal(t *testing.T) {
	for n := int64(1); n < 1<<22; n = n*3/2 + 1 {
		l := n + paddingFrameSize
		padded := PaddedSize(n)

		e := math.Floor(math.Log2(float64(l)))
		width := int64(1)
		if z := e - math.Floor(math.Log2(e)) - 1; z >= 1 {
			width = int64(1) << int(z)
		}

		if padded%width != 0 {
			t.Fatalf("PaddedSize(%d) = %d, not a multiple of the %d-byte bucket", n, padded, width)
		}
		if padded-width >= l {
			t.Fatalf("PaddedSize(%d) = %d, a whole %d-byte bucket above the framed %d", n, padded, width, l)
		}
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

	// The unpadded helper leaks exactly what the padded one hides: the same
	// three payloads have to seal to three distinguishable sizes. Comparing a
	// single unpadded seal against first would also pass if two of the three
	// collided, which is the property under test.
	plainDir := t.TempDir()
	seen := make(map[int64]int, len(sizes))
	for _, n := range sizes {
		srcPath := filepath.Join(plainDir, "plain.bin")
		if err := os.WriteFile(srcPath, randomData(t, n), filePerm); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}
		sealedPath := filepath.Join(plainDir, "plain.bin.enc")
		if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
			t.Fatalf("SealFile error: %v", err)
		}
		info, err := os.Stat(sealedPath)
		if err != nil {
			t.Fatalf("Stat error: %v", err)
		}
		if prev, dup := seen[info.Size()]; dup {
			t.Errorf("unpadded payloads %d and %d both sealed to %d bytes", prev, n, info.Size())
		}
		if info.Size() == first {
			t.Errorf("unpadded payload %d sealed to the padded size %d", n, first)
		}
		seen[info.Size()] = n
		if err := os.Remove(sealedPath); err != nil {
			t.Fatalf("Remove error: %v", err)
		}
	}
	if len(seen) != len(sizes) {
		t.Errorf("unpadded seals produced %d distinct sizes, want %d", len(seen), len(sizes))
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

// sealAsPadded seals plain as a stream carrying the padded format's domain
// tag, so a hand-built frame reaches the frame checks instead of stopping at
// authentication. SealPaddedStream cannot be used for these, since it writes a
// correct frame by construction.
func sealAsPadded(t *testing.T, s *Scheme, masterKey, plain, aad []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := s.SealStreamAAD(masterKey, &buf, bytes.NewReader(plain), paddedAAD(aad)); err != nil {
		t.Fatalf("SealStreamAAD error: %v", err)
	}
	return buf.Bytes()
}

// notAFrame is arbitrary content that cannot be read as a padding frame. Plain
// random bytes start with paddingVersion once every 256 runs, and the reader
// then fails on the length instead of the version byte, so a test asserting
// ErrNoPaddingFrame over random data is a flake rather than a check.
func notAFrame(t *testing.T, n int) []byte {
	t.Helper()
	b := randomData(t, n)
	if n > 0 {
		b[0] = paddingVersion + 1
	}
	return b
}

// TestOpenPaddedStreamRejectsPlainStream is what the AAD domain tag buys: a
// plain stream can no longer reach the padded frame checks at all, so no
// plaintext that happens to start 0x01 can be mistaken for a padded payload.
// The cost is that the failure is ErrStreamAuth, indistinguishable from a wrong
// key, so the documented recipe is to retry with the plain reader.
func TestOpenPaddedStreamRejectsPlainStream(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// a plaintext deliberately shaped like a frame: version byte, then a
	// big-endian length that matches the payload that follows
	payload := randomData(t, 4096)
	plain := make([]byte, paddingFrameSize)
	plain[0] = paddingVersion
	binary.BigEndian.PutUint64(plain[1:], uint64(len(payload)))
	plain = append(plain, payload...)

	var sealed bytes.Buffer
	if _, err := s.SealStream(masterKey, &sealed, bytes.NewReader(plain)); err != nil {
		t.Fatalf("SealStream error: %v", err)
	}
	blob := sealed.Bytes()

	if _, err := s.OpenPaddedStream(masterKey, io.Discard, bytes.NewReader(blob)); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("plain stream opened as padded: err = %v, want ErrStreamAuth", err)
	}

	// the documented way back: the plain reader still opens it
	var out bytes.Buffer
	if _, err := s.OpenStream(masterKey, &out, bytes.NewReader(blob)); err != nil {
		t.Fatalf("OpenStream error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("plain round-trip differs")
	}

	// and the reverse direction is closed too
	var padded bytes.Buffer
	if _, err := s.SealPaddedStream(masterKey, &padded, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	if _, err := s.OpenStream(masterKey, io.Discard, bytes.NewReader(padded.Bytes())); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("padded stream opened as plain: err = %v, want ErrStreamAuth", err)
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

	// domain-separated AAD, so this never reaches the frame checks
	if _, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "plain.out"), sealedPath); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("open unpadded stream: err = %v, want ErrStreamAuth", err)
	}
}

func TestOpenPaddedFileRejectsShortPayload(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// a frame promising more payload than the stream carries
	var frame [paddingFrameSize]byte
	frame[0] = paddingVersion
	frame[8] = 0xFF
	sealedPath := writeTempFile(t, "frame.enc", sealAsPadded(t, s, masterKey, frame[:], nil))
	dir := filepath.Dir(sealedPath)

	// A frame was read and the stream then contradicted it, so this is the
	// malformed case rather than the "predates padding" one.
	_, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "frame.out"), sealedPath)
	if !errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("open truncated frame: err = %v, want ErrPaddingMalformed", err)
	}
	if !errors.Is(err, ErrNotPadded) {
		t.Error("ErrPaddingMalformed no longer matches ErrNotPadded")
	}
}

func TestOpenPaddedFileRejectsEmptyPlaintext(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// an empty untagged stream stops at authentication, one step earlier
	srcPath := writeTempFile(t, "empty.bin", nil)
	dir := filepath.Dir(srcPath)
	sealedPath := filepath.Join(dir, "empty.enc")
	if _, err := s.SealFile(masterKey, sealedPath, srcPath); err != nil {
		t.Fatalf("SealFile error: %v", err)
	}
	if _, err := s.OpenPaddedFile(masterKey, filepath.Join(dir, "untagged.out"), sealedPath); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("open empty unpadded stream: err = %v, want ErrStreamAuth", err)
	}

	// an empty tagged one does reach the frame check, and has no frame
	tagged := writeTempFile(t, "empty-tagged.enc", sealAsPadded(t, s, masterKey, nil, nil))
	outPath := filepath.Join(filepath.Dir(tagged), "empty.out")
	if _, err := s.OpenPaddedFile(masterKey, outPath, tagged); !errors.Is(err, ErrNoPaddingFrame) {
		t.Errorf("open empty tagged stream: err = %v, want ErrNoPaddingFrame", err)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Error("partial output was not removed")
	}
}

func TestSealPaddedFileRejectsIrregularSource(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	dir := t.TempDir()

	dstPath := filepath.Join(dir, "out.enc")
	_, err := s.SealPaddedFile(masterKey, dstPath, dir)
	if !errors.Is(err, ErrSourceIrregular) {
		t.Errorf("seal a directory: err = %v, want ErrSourceIrregular", err)
	}
	// a source with no size at all is not a source that missed its size
	if errors.Is(err, ErrSourceShort) || errors.Is(err, ErrSourceLong) {
		t.Errorf("err = %v, want neither direction sentinel", err)
	}
	if _, err := os.Stat(dstPath); !os.IsNotExist(err) {
		t.Error("the destination opened for the failed seal was not removed")
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

	_, err := s.SealPaddedFile(masterKey, sealedPath, srcPath)
	if err == nil {
		t.Fatal("SealPaddedFile overwrote an existing destination")
	}
	// O_EXCL, not a size or format complaint
	if !errors.Is(err, os.ErrExist) {
		t.Errorf("err = %v, want it to match os.ErrExist", err)
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
	_, err := s.SealPaddedStreamAAD(masterKey, &out, bytes.NewReader(payload), int64(len(payload))+1024, nil)
	if !errors.Is(err, ErrSourceShort) {
		t.Fatalf("short source: err = %v, want ErrSourceShort", err)
	}

	// The doc tells a stream caller to discard dst. Whatever is in it must not
	// open as a stream of either kind, or the failure would be recoverable into
	// a payload that was never fully delivered.
	blob := out.Bytes()
	if _, err := s.OpenPaddedStream(masterKey, io.Discard, bytes.NewReader(blob)); err == nil {
		t.Error("the partial stream left in dst opened as padded")
	}
	if _, err := s.OpenStream(masterKey, io.Discard, bytes.NewReader(blob)); err == nil {
		t.Error("the partial stream left in dst opened as plain")
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

// TestSealOpenPaddedStream round-trips the padded form entirely in memory,
// which is the point of the stream variant: a payload that is not already a
// file never has to be staged on disk to be padded.
func TestSealOpenPaddedStream(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			payload := randomData(t, tt.n)

			var sealed bytes.Buffer
			n, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(tt.n))
			if err != nil {
				t.Fatalf("SealPaddedStream error: %v", err)
			}
			if n != int64(tt.n) {
				t.Errorf("sealed = %d, want %d payload bytes", n, tt.n)
			}
			if want := sealedSize(int(PaddedSize(int64(tt.n)))); sealed.Len() != want {
				t.Errorf("sealed size = %d, want %d", sealed.Len(), want)
			}

			var opened bytes.Buffer
			got, err := s.OpenPaddedStream(masterKey, &opened, &sealed)
			if err != nil {
				t.Fatalf("OpenPaddedStream error: %v", err)
			}
			if got != int64(tt.n) {
				t.Errorf("opened = %d, want %d", got, tt.n)
			}
			if !bytes.Equal(opened.Bytes(), payload) {
				t.Error("round-tripped payload differs")
			}
		})
	}
}

// TestPaddedStreamAAD checks that context binding reaches every chunk of a
// padded stream, padding chunks included.
func TestPaddedStreamAAD(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)
	aad := []byte("user:42:upload")

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStreamAAD(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload)), aad); err != nil {
		t.Fatalf("SealPaddedStreamAAD error: %v", err)
	}
	blob := sealed.Bytes()

	var opened bytes.Buffer
	if _, err := s.OpenPaddedStreamAAD(masterKey, &opened, bytes.NewReader(blob), aad); err != nil {
		t.Fatalf("OpenPaddedStreamAAD error: %v", err)
	}
	if !bytes.Equal(opened.Bytes(), payload) {
		t.Error("round-tripped payload differs")
	}

	opened.Reset()
	if _, err := s.OpenPaddedStreamAAD(masterKey, &opened, bytes.NewReader(blob), []byte("user:7:upload")); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("wrong aad: err = %v, want ErrStreamAuth", err)
	}
	if opened.Len() != 0 {
		t.Errorf("wrong aad still wrote %d bytes to dst", opened.Len())
	}
}

// TestPaddedStreamAndFileInterop pins the two entry points to one format: a
// stream sealed in memory opens as a file and vice versa, so exporting the
// stream form did not fork the padded layout.
func TestPaddedStreamAndFileInterop(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)
	aad := []byte("interop")

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStreamAAD(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload)), aad); err != nil {
		t.Fatalf("SealPaddedStreamAAD error: %v", err)
	}

	// stream -> file
	sealedPath := writeTempFile(t, "stream.enc", sealed.Bytes())
	dir := filepath.Dir(sealedPath)
	openedPath := filepath.Join(dir, "stream.out")
	if _, err := s.OpenPaddedFileAAD(masterKey, openedPath, sealedPath, aad); err != nil {
		t.Fatalf("OpenPaddedFileAAD error: %v", err)
	}
	back, err := os.ReadFile(openedPath) // #nosec G304
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Error("stream-sealed payload differs after opening as a file")
	}

	// file -> stream
	srcPath := writeTempFile(t, "file.bin", payload)
	filePath := filepath.Join(filepath.Dir(srcPath), "file.enc")
	if _, err := s.SealPaddedFileAAD(masterKey, filePath, srcPath, aad); err != nil {
		t.Fatalf("SealPaddedFileAAD error: %v", err)
	}
	fromFile, err := os.ReadFile(filePath) // #nosec G304
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(fromFile) != sealed.Len() {
		t.Errorf("file-sealed size = %d, stream-sealed = %d", len(fromFile), sealed.Len())
	}

	var opened bytes.Buffer
	if _, err := s.OpenPaddedStreamAAD(masterKey, &opened, bytes.NewReader(fromFile), aad); err != nil {
		t.Fatalf("OpenPaddedStreamAAD error: %v", err)
	}
	if !bytes.Equal(opened.Bytes(), payload) {
		t.Error("file-sealed payload differs after opening as a stream")
	}
}

// countingWriter records how many bytes reached the destination.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// TestSealPaddedStreamFailsBeforePadding pins the cost of a wrong size. The
// mismatch has to be caught at the payload boundary, before the padding is
// generated: a caller that declares a huge size and delivers almost nothing
// must not be able to make the sealer write the whole Padmé bucket to dst
// first. Sealing to a real destination that would be an amplified write of
// attacker-chosen size.
func TestSealPaddedStreamFailsBeforePadding(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	for _, declared := range []int64{1 << 20, 1 << 30, 1 << 40} {
		var w countingWriter
		_, err := s.SealPaddedStream(masterKey, &w, bytes.NewReader([]byte{0}), declared)
		if !errors.Is(err, ErrSourceShort) {
			t.Fatalf("declared %d: err = %v, want ErrSourceShort", declared, err)
		}
		// The header plus the one chunk the sealer may have flushed while
		// waiting to find out whether more data followed. The padding alone
		// would be orders of magnitude more.
		if limit := int64(streamHeaderSize + testChunkSize + TagSize); w.n > limit {
			t.Errorf("declared %d: wrote %d bytes before failing, want <= %d", declared, w.n, limit)
		}
	}
}

// TestSealPaddedStreamRejectsTrailingBytes covers the other direction: a src
// that keeps going past its declared size must fail rather than be silently
// truncated to a well-formed frame.
func TestSealPaddedStreamRejectsTrailingBytes(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, testChunkSize*2)

	// declare exactly one byte less than src holds: the smallest overrun the
	// probe can see, and the one a length check on whole chunks would miss
	var out bytes.Buffer
	_, err := s.SealPaddedStream(masterKey, &out, bytes.NewReader(payload), int64(len(payload)-1))
	if !errors.Is(err, ErrSourceLong) {
		t.Errorf("err = %v, want ErrSourceLong", err)
	}
}

// stutterReader returns (0, nil) before every real read. That is legal for an
// io.Reader, and exactReader must not mistake it for the end of the payload.
type stutterReader struct {
	r     io.Reader
	ready bool
}

func (s *stutterReader) Read(p []byte) (int, error) {
	if !s.ready {
		s.ready = true
		return 0, nil
	}
	s.ready = false
	return s.r.Read(p)
}

func TestSealPaddedStreamHandlesEmptyReads(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, testChunkSize+123)

	var sealed bytes.Buffer
	n, err := s.SealPaddedStream(masterKey, &sealed, &stutterReader{r: bytes.NewReader(payload)}, int64(len(payload)))
	if err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("sealed = %d, want %d", n, len(payload))
	}

	var opened bytes.Buffer
	if _, err := s.OpenPaddedStream(masterKey, &opened, &sealed); err != nil {
		t.Fatalf("OpenPaddedStream error: %v", err)
	}
	if !bytes.Equal(opened.Bytes(), payload) {
		t.Error("round-tripped payload differs")
	}
}

// deadReader delivers its payload and then answers (0, nil) forever: legal per
// the io.Reader contract, which says a caller should read that as "nothing
// happened", but never EOF and never an error. io.Copy, io.ReadAll and
// io.ReadFull all spin on such a reader; exactReader's own probe loop must not.
type deadReader struct{ r io.Reader }

func (d *deadReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, nil // swallow the EOF: (0, nil) from here on
	}
	return n, err
}

func TestSealPaddedStreamRejectsStalledSource(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, testChunkSize*2)

	// Run it off the test goroutine so a regression fails in seconds instead
	// of hanging until the package test timeout.
	done := make(chan error, 1)
	go func() {
		_, err := s.SealPaddedStream(masterKey, io.Discard,
			&deadReader{r: bytes.NewReader(payload)}, int64(len(payload)))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, io.ErrNoProgress) {
			t.Errorf("err = %v, want io.ErrNoProgress", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SealPaddedStream never returned: the probe loop is spinning")
	}
}

// closedAfterEOF returns its payload together with io.EOF, then fails any
// further read the way a reader that closes itself at EOF would. exactReader
// must not read it again: the payload was complete, so re-reading would turn a
// good seal into an error.
type closedAfterEOF struct {
	data []byte
	read bool
}

func (c *closedAfterEOF) Read(p []byte) (int, error) {
	if c.read {
		return 0, os.ErrClosed
	}
	c.read = true
	n := copy(p, c.data)
	if n < len(c.data) {
		c.data = c.data[n:]
		c.read = false
		return n, nil
	}
	return n, io.EOF // final bytes and EOF in one call
}

func TestSealPaddedStreamDoesNotReadPastEOF(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, testChunkSize+321)

	var sealed bytes.Buffer
	n, err := s.SealPaddedStream(masterKey, &sealed, &closedAfterEOF{data: payload}, int64(len(payload)))
	if err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("sealed = %d, want %d", n, len(payload))
	}

	var opened bytes.Buffer
	if _, err := s.OpenPaddedStream(masterKey, &opened, &sealed); err != nil {
		t.Fatalf("OpenPaddedStream error: %v", err)
	}
	if !bytes.Equal(opened.Bytes(), payload) {
		t.Error("round-tripped payload differs")
	}
}

// countingSource records how many times it was read, so a test can prove a
// failed exactReader stopped consulting it.
type countingSource struct {
	r     io.Reader
	reads int   // Read calls
	n     int64 // bytes delivered
}

func (c *countingSource) Read(p []byte) (int, error) {
	c.reads++
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func TestExactReaderErrorIsSticky(t *testing.T) {
	src := &countingSource{r: bytes.NewReader(make([]byte, 64))}
	e := &exactReader{r: src, left: 8}

	buf := make([]byte, 8)
	if _, err := e.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	_, first := e.Read(buf) // 56 bytes of src remain unread
	if !errors.Is(first, ErrSourceLong) {
		t.Fatalf("err = %v, want ErrSourceLong", first)
	}

	before := src.reads
	for i := range 3 {
		_, err := e.Read(buf)
		if err != first {
			t.Errorf("retry %d: err = %v, want the identical sticky error", i, err)
		}
	}
	if src.reads != before {
		t.Errorf("source was read %d more times after the failure", src.reads-before)
	}
}

func TestExactReaderEOFIsSticky(t *testing.T) {
	e := &exactReader{r: bytes.NewReader(make([]byte, 8)), left: 8}
	if _, err := e.Read(make([]byte, 8)); err != nil {
		t.Fatalf("first read: %v", err)
	}
	for i := range 3 {
		if _, err := e.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
			t.Errorf("read %d after the payload: err = %v, want io.EOF", i, err)
		}
	}
}

func TestExactReaderZeroLengthReadIsNoOp(t *testing.T) {
	// left == 0 from the start, so a zero-length read would otherwise fall
	// straight into the probe and consume a byte of the source.
	src := &countingSource{r: bytes.NewReader([]byte("trailing"))}
	e := &exactReader{r: src, left: 0}

	n, err := e.Read(nil)
	if n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := e.Read([]byte{}); n != 0 || err != nil {
		t.Errorf("Read(empty) = (%d, %v), want (0, nil)", n, err)
	}
	if src.reads != 0 {
		t.Errorf("source was read %d times by a zero-length read", src.reads)
	}

	// A real read still detects the trailing data.
	if _, err := e.Read(make([]byte, 4)); !errors.Is(err, ErrSourceLong) {
		t.Errorf("err = %v, want ErrSourceLong", err)
	}
}

// overrunReader claims to have written more bytes than the buffer holds, which
// the io.Reader contract forbids. Left unchecked it drives exactReader.left
// negative and panics on the next slice expression.
type overrunReader struct{}

func (overrunReader) Read(p []byte) (int, error) { return len(p) + 1, nil }

func TestExactReaderRejectsInvalidReadCount(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked instead of failing closed: %v", r)
		}
	}()

	e := &exactReader{r: overrunReader{}, left: 4096}
	if _, err := e.Read(make([]byte, 64)); err == nil {
		t.Fatal("invalid read count accepted")
	}
	// and it stays failed rather than slicing on a negative remainder
	if _, err := e.Read(make([]byte, 64)); err == nil {
		t.Error("reader recovered after an invalid read count")
	}
}

func TestSealPaddedStreamReportsMismatchDirection(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, 4096)

	short := func() error {
		_, err := s.SealPaddedStream(masterKey, io.Discard, bytes.NewReader(payload), int64(len(payload))+1024)
		return err
	}()
	long := func() error {
		_, err := s.SealPaddedStream(masterKey, io.Discard, bytes.NewReader(payload), int64(len(payload))-1024)
		return err
	}()

	for _, err := range []error{short, long} {
		if !errors.Is(err, ErrSourceSize) {
			t.Fatalf("err = %v, want ErrSourceSize", err)
		}
	}
	if short.Error() == long.Error() {
		t.Errorf("short and long report the same message: %q", short.Error())
	}
	// and they are branchable, not just distinguishable by message
	if !errors.Is(short, ErrSourceShort) || errors.Is(short, ErrSourceLong) {
		t.Errorf("short source: want ErrSourceShort only, got %v", short)
	}
	if !errors.Is(long, ErrSourceLong) || errors.Is(long, ErrSourceShort) {
		t.Errorf("long source: want ErrSourceLong only, got %v", long)
	}
	t.Logf("short: %v", short)
	t.Logf("long:  %v", long)
}

// stalledFill returns (0, nil) forever without ever finishing the payload, so
// the stall happens while filling p rather than inside the end-of-payload
// probe. Both paths have to be bounded or the caller's io.ReadFull spins.
type stalledFill struct{}

func (stalledFill) Read([]byte) (int, error) { return 0, nil }

func TestExactReaderBoundsEmptyReadsWhileFilling(t *testing.T) {
	e := &exactReader{r: stalledFill{}, left: 4096}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			if _, err := e.Read(buf); err != nil {
				done <- err
				return
			}
		}
	}()

	select {
	case err := <-done:
		if !errors.Is(err, io.ErrNoProgress) {
			t.Errorf("err = %v, want io.ErrNoProgress", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the fill path never gave up on a stalled source")
	}
}

// TestSealPaddedStreamFramedSource documents what the trailing-data probe costs
// a caller that is sealing one frame out of a longer stream: read the frame
// directly and the probe consumes a byte of whatever follows, so the frame must
// be handed over as an io.LimitReader instead.
func TestSealPaddedStreamFramedSource(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	frame := randomData(t, 2048)
	trailer := []byte("NEXT-FRAME-HEADER")

	t.Run("raw reader is rejected and loses a byte", func(t *testing.T) {
		src := bytes.NewReader(append(append([]byte{}, frame...), trailer...))
		_, err := s.SealPaddedStream(masterKey, io.Discard, src, int64(len(frame)))
		if !errors.Is(err, ErrSourceLong) {
			t.Fatalf("err = %v, want ErrSourceLong", err)
		}
		rest, err := io.ReadAll(src)
		if err != nil {
			t.Fatalf("ReadAll error: %v", err)
		}
		if len(rest) != len(trailer)-1 {
			t.Errorf("trailer has %d bytes left, want %d (the probe eats one)", len(rest), len(trailer)-1)
		}
	})

	t.Run("LimitReader seals and leaves the trailer intact", func(t *testing.T) {
		src := bytes.NewReader(append(append([]byte{}, frame...), trailer...))
		var sealed bytes.Buffer
		n, err := s.SealPaddedStream(masterKey, &sealed, io.LimitReader(src, int64(len(frame))), int64(len(frame)))
		if err != nil {
			t.Fatalf("SealPaddedStream error: %v", err)
		}
		if n != int64(len(frame)) {
			t.Errorf("sealed = %d, want %d", n, len(frame))
		}
		rest, err := io.ReadAll(src)
		if err != nil {
			t.Fatalf("ReadAll error: %v", err)
		}
		if !bytes.Equal(rest, trailer) {
			t.Errorf("trailer = %q, want %q untouched", rest, trailer)
		}

		var opened bytes.Buffer
		if _, err := s.OpenPaddedStream(masterKey, &opened, &sealed); err != nil {
			t.Fatalf("OpenPaddedStream error: %v", err)
		}
		if !bytes.Equal(opened.Bytes(), frame) {
			t.Error("round-tripped frame differs")
		}
	})
}

// TestExactReaderRejectsNegativeRemainder covers the guard that keeps p[:e.left]
// from panicking. SealPaddedStreamAAD screens a negative size out through
// PaddedSize, so the only way in is to build the reader directly.
func TestExactReaderRejectsNegativeRemainder(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked instead of failing closed: %v", r)
		}
	}()

	src := &countingSource{r: bytes.NewReader(make([]byte, 32))}
	e := &exactReader{r: src, left: -5}
	_, err := e.Read(make([]byte, 8))
	if !errors.Is(err, errNegativeRemainder) {
		t.Fatalf("err = %v, want errNegativeRemainder", err)
	}
	// the blame belongs to the construction site, not to r
	if errors.Is(err, errBadReadCount) || errors.Is(err, ErrSourceSize) {
		t.Errorf("err = %v, want it to name neither the source nor its size", err)
	}
	if src.reads != 0 {
		t.Errorf("source was read %d times on a negative remainder", src.reads)
	}
	if _, again := e.Read(make([]byte, 8)); again != err {
		t.Errorf("retry: err = %v, want the identical sticky error", again)
	}
}

// TestExactReaderEndIsVerifiedNotAssumed pins the gap that reachedEnd closes:
// a caller that stops the moment it has its bytes never reaches the
// trailing-data check, so SealPaddedStreamAAD verifies rather than assumes it.
func TestExactReaderEndIsVerifiedNotAssumed(t *testing.T) {
	// io.ReadFull stops as soon as it has what it asked for.
	e := &exactReader{r: bytes.NewReader(make([]byte, 64)), left: 8}
	if _, err := io.ReadFull(e, make([]byte, 8)); err != nil {
		t.Fatalf("ReadFull error: %v", err)
	}
	if e.reachedEnd() {
		t.Error("reachedEnd is true although the source was never driven to EOF")
	}

	// The seal path does drive it there, on every payload shape.
	s := streamScheme()
	masterKey := newMasterKey(t)
	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			payload := randomData(t, tt.n)
			checked := &exactReader{r: bytes.NewReader(payload), left: int64(tt.n)}
			var out bytes.Buffer
			// mirror what SealPaddedStreamAAD builds, so the assertion is
			// about the drain and not about the padding arithmetic
			if _, err := s.SealStream(masterKey, &out, io.MultiReader(checked, bytes.NewReader(nil))); err != nil {
				t.Fatalf("SealStream error: %v", err)
			}
			if !checked.reachedEnd() {
				t.Error("the seal path left the payload reader short of its end")
			}
		})
	}
}

// erroringAtEnd delivers exactly its payload, never signals EOF, and fails the
// next read: the failure therefore happens inside the trailing-data check.
type erroringAtEnd struct {
	r   io.Reader
	err error
}

func (e *erroringAtEnd) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		if n > 0 {
			return n, nil // hold the EOF back so the probe is what fails
		}
		return 0, e.err
	}
	return n, err
}

func TestExactReaderAnnotatesDrainFailure(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, 2048)
	sentinel := errors.New("disk fell over")

	_, err := s.SealPaddedStream(masterKey, io.Discard,
		&erroringAtEnd{r: bytes.NewReader(payload), err: sentinel}, int64(len(payload)))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the source error", err)
	}
	if !strings.Contains(err.Error(), "past the declared size") {
		t.Errorf("err = %q, want it to name the drain check", err)
	}
	t.Logf("annotated: %v", err)
}

// TestOpenPaddedStreamChecksPaddingLength builds well-formed padded frames with
// deliberately wrong padding lengths and checks the drain-time comparison
// against PaddedSize rejects them. Nothing else in the format would notice: the
// chunks authenticate and the payload is intact, so without the check a sealer
// using a different rule stays silently readable.
func TestOpenPaddedStreamChecksPaddingLength(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	const payloadSize = 4096
	payload := randomData(t, payloadSize)
	want := PaddedSize(payloadSize)

	// hand-build the plaintext the sealer would have produced, then vary only
	// how much padding follows
	frame := make([]byte, paddingFrameSize)
	frame[0] = paddingVersion
	binary.BigEndian.PutUint64(frame[1:], payloadSize)

	build := func(t *testing.T, padding int64) []byte {
		t.Helper()
		plain := append(append([]byte{}, frame...), payload...)
		plain = append(plain, make([]byte, padding)...)
		return sealAsPadded(t, s, masterKey, plain, nil)
	}

	correct := want - paddingFrameSize - payloadSize
	tests := []struct {
		name    string
		padding int64
		wantErr bool
	}{
		{name: "exact", padding: correct},
		{name: "oneShort", padding: correct - 1, wantErr: true},
		{name: "oneLong", padding: correct + 1, wantErr: true},
		{name: "none", padding: 0, wantErr: true},
		{name: "doubled", padding: correct * 2, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			n, err := s.OpenPaddedStream(masterKey, &out, bytes.NewReader(build(t, tt.padding)))
			switch {
			case tt.wantErr && !errors.Is(err, ErrPaddingMalformed):
				t.Errorf("err = %v, want ErrPaddingMalformed", err)
			case !tt.wantErr && err != nil:
				t.Errorf("unexpected error: %v", err)
			case !tt.wantErr && n != payloadSize:
				t.Errorf("n = %d, want %d", n, payloadSize)
			}
			// the payload still reaches dst either way, which is exactly why
			// the doc calls dst provisional until the call returns nil
			if !bytes.Equal(out.Bytes(), payload) {
				t.Error("payload written to dst differs")
			}
		})
	}
}

func TestOpenPaddedStreamAcceptsEverySealedSize(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// the new length check must not reject anything the sealer produces
	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			payload := randomData(t, tt.n)
			var sealed bytes.Buffer
			if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(tt.n)); err != nil {
				t.Fatalf("SealPaddedStream error: %v", err)
			}
			var out bytes.Buffer
			n, err := s.OpenPaddedStream(masterKey, &out, &sealed)
			if err != nil {
				t.Fatalf("OpenPaddedStream error: %v", err)
			}
			if n != int64(tt.n) {
				t.Errorf("opened = %d, want %d", n, tt.n)
			}
			if !bytes.Equal(out.Bytes(), payload) {
				t.Error("round-tripped payload differs")
			}
		})
	}
}

// TestPaddedPlaintextLayout pins the sealed plaintext byte for byte: the
// documented frame, then the payload, then zeros. Every other test in this file
// would pass just as well if the sealer framed the length in the wrong byte
// order (both ends agree), or padded with whatever the buffer happened to hold
// (the reader discards the padding unread), and the second would leak memory
// contents into the ciphertext.
func TestPaddedPlaintextLayout(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, testChunkSize+321)

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	blob := sealed.Bytes()

	// nothing on the outside announces padding: an ordinary stream header
	if blob[0] != streamVersion {
		t.Errorf("first byte = %#x, want the ordinary streamVersion %#x", blob[0], streamVersion)
	}

	r, err := s.OpenReaderAAD(masterKey, bytes.NewReader(blob), paddedAAD(nil))
	if err != nil {
		t.Fatalf("OpenReaderAAD error: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	want := PaddedSize(int64(len(payload)))
	if int64(len(plain)) != want {
		t.Fatalf("plaintext = %d bytes, want PaddedSize = %d", len(plain), want)
	}
	if plain[0] != paddingVersion {
		t.Errorf("frame version = %#x, want %#x", plain[0], paddingVersion)
	}
	if got := binary.BigEndian.Uint64(plain[1:paddingFrameSize]); got != uint64(len(payload)) {
		t.Errorf("framed length = %d big-endian, want %d", got, len(payload))
	}

	body := plain[paddingFrameSize:]
	if !bytes.Equal(body[:len(payload)], payload) {
		t.Error("payload is not where the frame says it is")
	}
	tail := body[len(payload):]
	if len(tail) == 0 {
		t.Fatal("this payload produced no padding, so the tail proves nothing")
	}
	for i, b := range tail {
		if b != 0 {
			t.Fatalf("padding byte %d of %d = %#x, want zero", i, len(tail), b)
		}
	}
}

// TestPaddedErrorMessagesReadCorrectly guards the wrapped strings: an umbrella
// that names a cause makes its own sentinels contradict themselves in a log.
func TestPaddedErrorMessagesReadCorrectly(t *testing.T) {
	// The umbrellas are pinned verbatim rather than screened for known bad
	// words: nothing structural distinguishes a class from a cause, and it is
	// the wording that has to stay a class. Anything naming a cause here, as
	// the pre-split "sealed stream carries no padded payload" did, contradicts
	// its own sentinels once fmt.Errorf concatenates the two.
	for _, tt := range []struct {
		err  error
		want string
	}{
		{ErrNotPadded, "envelope: not a readable padded stream"},
		{ErrSourceSize, "envelope: source size is not usable for padding"},
	} {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("umbrella = %q, want %q", got, tt.want)
		}
	}

	causes := map[error]map[string]error{}
	for _, tt := range []struct {
		err      error
		umbrella error
	}{
		{ErrNoPaddingFrame, ErrNotPadded},
		{ErrPaddingMalformed, ErrNotPadded},
		{ErrSourceIrregular, ErrSourceSize},
		{ErrSourceShort, ErrSourceSize},
		{ErrSourceLong, ErrSourceSize},
	} {
		if !errors.Is(tt.err, tt.umbrella) {
			t.Errorf("%v does not wrap %v", tt.err, tt.umbrella)
			continue
		}
		prefix := tt.umbrella.Error() + ": "
		if !strings.HasPrefix(tt.err.Error(), prefix) {
			t.Errorf("%q does not read as an extension of %q", tt.err, tt.umbrella)
			continue
		}
		cause := strings.TrimPrefix(tt.err.Error(), prefix)
		if cause == "" {
			t.Errorf("%q adds nothing to its umbrella", tt.err)
		}
		if causes[tt.umbrella] == nil {
			causes[tt.umbrella] = map[string]error{}
		}
		if twin, dup := causes[tt.umbrella][cause]; dup {
			t.Errorf("%v and %v read alike, so neither says which case it is", twin, tt.err)
		}
		causes[tt.umbrella][cause] = tt.err
		t.Logf("%v", tt.err)
	}
}

func TestOpenPaddedStreamDistinguishesUnpaddedFromBroken(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// authenticates as padded but carries no frame: a newer padded format would
	// look like this to this reader
	noFrame := sealAsPadded(t, s, masterKey, notAFrame(t, 512), nil)
	_, err := s.OpenPaddedStream(masterKey, io.Discard, bytes.NewReader(noFrame))
	if !errors.Is(err, ErrNoPaddingFrame) || errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("no frame: err = %v, want ErrNoPaddingFrame", err)
	}

	// too short to hold a frame at all, which is the other ErrNoPaddingFrame path
	short := sealAsPadded(t, s, masterKey, []byte{paddingVersion, 0, 0}, nil)
	_, err = s.OpenPaddedStream(masterKey, io.Discard, bytes.NewReader(short))
	if !errors.Is(err, ErrNoPaddingFrame) || errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("truncated frame: err = %v, want ErrNoPaddingFrame", err)
	}

	// a real frame followed by a stream that contradicts it
	frame := make([]byte, paddingFrameSize)
	frame[0] = paddingVersion
	binary.BigEndian.PutUint64(frame[1:], 1<<20)
	broken := sealAsPadded(t, s, masterKey, frame, nil)
	_, err = s.OpenPaddedStream(masterKey, io.Discard, bytes.NewReader(broken))
	if !errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("broken frame: err = %v, want ErrPaddingMalformed", err)
	}

	// a declared length that does not fit in an int64: rejected on the guard,
	// before it is ever used as a copy length
	huge := make([]byte, paddingFrameSize)
	huge[0] = paddingVersion
	binary.BigEndian.PutUint64(huge[1:], math.MaxUint64)
	var out bytes.Buffer
	_, err = s.OpenPaddedStream(masterKey, &out, bytes.NewReader(sealAsPadded(t, s, masterKey, huge, nil)))
	if !errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("oversized length: err = %v, want ErrPaddingMalformed", err)
	}
	if out.Len() != 0 {
		t.Errorf("wrote %d bytes for a length the reader rejected", out.Len())
	}
}

// TestOpenPaddedStreamBoundsTheDrain checks the reader stops at the padding
// PaddedSize calls for instead of consuming whatever follows. Only a key holder
// can build such a stream, so this is about work done before complaining, not
// about forgery.
func TestOpenPaddedStreamBoundsTheDrain(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	const payloadSize = 1024
	payload := randomData(t, payloadSize)

	frame := make([]byte, paddingFrameSize)
	frame[0] = paddingVersion
	binary.BigEndian.PutUint64(frame[1:], payloadSize)

	plain := append(append([]byte{}, frame...), payload...)
	plain = append(plain, make([]byte, 4<<20)...) // far more padding than any bucket
	sealed := sealAsPadded(t, s, masterKey, plain, nil)

	src := &countingSource{r: bytes.NewReader(sealed)}
	_, err := s.OpenPaddedStream(masterKey, io.Discard, src)
	if !errors.Is(err, ErrPaddingMalformed) {
		t.Fatalf("err = %v, want ErrPaddingMalformed", err)
	}

	// the whole blob is over 4 MiB; stopping at the expected padding plus the
	// one-byte probe should cost only a handful of chunks
	want := PaddedSize(payloadSize)
	if limit := int64(sealedSize(int(want))) + testChunkSize + TagSize; src.n > limit {
		t.Errorf("read %d bytes of a %d byte stream, want <= %d", src.n, len(sealed), limit)
	}
	t.Logf("read %d of %d sealed bytes before rejecting", src.n, len(sealed))
}

// The padded reader is the pull form of OpenPaddedStream, so it has to be
// usable everywhere an io.Reader is: io.Copy takes the WriteTo path, and an
// HTTP layer that closes what it reads takes the ReadCloser one.
var (
	_ io.ReadCloser = (*PaddedReader)(nil)
	_ io.WriterTo   = (*PaddedReader)(nil)
)

func TestOpenPaddedReaderRoundTrip(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			payload := randomData(t, tt.n)
			var sealed bytes.Buffer
			if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(tt.n)); err != nil {
				t.Fatalf("SealPaddedStream error: %v", err)
			}

			r, err := s.OpenPaddedReader(masterKey, &sealed)
			if err != nil {
				t.Fatalf("OpenPaddedReader error: %v", err)
			}
			if r.Size() != int64(tt.n) {
				t.Errorf("Size = %d, want %d", r.Size(), tt.n)
			}

			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Error("round-tripped payload differs")
			}
			// reading to EOF already authenticated the padding, so Close only
			// repeats the verdict, however often it is asked
			for i := range 2 {
				if err := r.Close(); err != nil {
					t.Errorf("Close %d after a clean read: %v", i, err)
				}
			}
		})
	}
}

// TestPaddedReaderSizeIsKnownBeforeTheBody is the reason the pull form exists:
// the payload length comes out of the authenticated frame before a byte of
// payload is handed over, so a handler can set Content-Length from it instead
// of recording the length beside the blob.
func TestPaddedReaderSizeIsKnownBeforeTheBody(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)
	aad := []byte("obj:42")

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStreamAAD(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload)), aad); err != nil {
		t.Fatalf("SealPaddedStreamAAD error: %v", err)
	}

	src := &countingSource{r: bytes.NewReader(sealed.Bytes())}
	r, err := s.OpenPaddedReaderAAD(masterKey, src, aad)
	if err != nil {
		t.Fatalf("OpenPaddedReaderAAD error: %v", err)
	}
	if r.Size() != int64(len(payload)) {
		t.Fatalf("Size = %d, want %d", r.Size(), len(payload))
	}
	// the frame rides in the first chunk, so the length is known after one
	// chunk rather than after the whole stream
	if limit := int64(streamHeaderSize + 2*(testChunkSize+TagSize)); src.n > limit {
		t.Errorf("read %d bytes to learn the size, want <= %d", src.n, limit)
	}

	// and the size is authentic: the wrong aad never gets that far
	if _, err := s.OpenPaddedReaderAAD(masterKey, bytes.NewReader(sealed.Bytes()), []byte("obj:7")); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("wrong aad: err = %v, want ErrStreamAuth", err)
	}
}

// TestPaddedReaderCloseCatchesBadPadding is why Close exists. Size invites the
// caller to ask for exactly that many bytes, which stops one call short of the
// padding check, so without Close a stream whose padding contradicts
// PaddedSize would be read as good.
func TestPaddedReaderCloseCatchesBadPadding(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	const payloadSize = 4096
	payload := randomData(t, payloadSize)

	frame := make([]byte, paddingFrameSize)
	frame[0] = paddingVersion
	binary.BigEndian.PutUint64(frame[1:], payloadSize)
	correct := PaddedSize(payloadSize) - paddingFrameSize - payloadSize

	build := func(t *testing.T, padding int64) []byte {
		t.Helper()
		plain := append(append([]byte{}, frame...), payload...)
		plain = append(plain, make([]byte, padding)...)
		return sealAsPadded(t, s, masterKey, plain, nil)
	}

	tests := []struct {
		name    string
		padding int64
		wantErr bool
	}{
		{name: "exact", padding: correct},
		{name: "oneShort", padding: correct - 1, wantErr: true},
		{name: "oneLong", padding: correct + 1, wantErr: true},
		{name: "none", padding: 0, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := s.OpenPaddedReader(masterKey, bytes.NewReader(build(t, tt.padding)))
			if err != nil {
				t.Fatalf("OpenPaddedReader error: %v", err)
			}

			// the Content-Length pattern: ask for Size bytes and stop
			got := make([]byte, r.Size())
			if _, err := io.ReadFull(r, got); err != nil {
				t.Fatalf("ReadFull error: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Error("payload differs")
			}

			err = r.Close()
			if tt.wantErr && !errors.Is(err, ErrPaddingMalformed) {
				t.Errorf("Close = %v, want ErrPaddingMalformed", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Close = %v, want nil", err)
			}
			// and the verdict does not change on a second ask
			if again := r.Close(); !errors.Is(again, err) {
				t.Errorf("second Close = %v, want %v", again, err)
			}
		})
	}
}

// TestPaddedReaderCloseEarlyIsIncomplete pins what closing without reading the
// payload does: it says so, rather than quietly draining however many gigabytes
// were skipped in order to reach the padding.
func TestPaddedReaderCloseEarlyIsIncomplete(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}

	src := &countingSource{r: bytes.NewReader(sealed.Bytes())}
	r, err := s.OpenPaddedReader(masterKey, src)
	if err != nil {
		t.Fatalf("OpenPaddedReader error: %v", err)
	}
	if _, err := io.ReadFull(r, make([]byte, 1)); err != nil {
		t.Fatalf("Read error: %v", err)
	}

	if err := r.Close(); !errors.Is(err, ErrIncompleteRead) {
		t.Errorf("Close = %v, want ErrIncompleteRead", err)
	}
	// nothing was drained to find that out
	if limit := int64(streamHeaderSize + 2*(testChunkSize+TagSize)); src.n > limit {
		t.Errorf("Close read on to %d bytes of a %d byte stream, want <= %d", src.n, sealed.Len(), limit)
	}
	// it stands outside both format umbrellas: the stream may be perfectly good
	if errors.Is(err, ErrNotPadded) || errors.Is(err, ErrSourceSize) {
		t.Errorf("err = %v, want it to blame neither the format nor a source", err)
	}
	// and it is terminal, so a later read cannot resume behind Close's back
	if _, err := r.Read(make([]byte, 8)); !errors.Is(err, ErrIncompleteRead) {
		t.Errorf("Read after Close = %v, want ErrIncompleteRead", err)
	}
	if err := r.Close(); !errors.Is(err, ErrIncompleteRead) {
		t.Errorf("second Close = %v, want ErrIncompleteRead", err)
	}
}

func TestOpenPaddedReaderRejectsBadStreams(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// not a stream at all: the header check fails before any padded reasoning
	if _, err := s.OpenPaddedReader(masterKey, bytes.NewReader([]byte("too short"))); !errors.Is(err, ErrBadStream) {
		t.Errorf("short input: err = %v, want ErrBadStream", err)
	}

	// a plain stream: stopped by the domain-separated AAD, as with the push form
	var plain bytes.Buffer
	if _, err := s.SealStream(masterKey, &plain, bytes.NewReader(randomData(t, 2048))); err != nil {
		t.Fatalf("SealStream error: %v", err)
	}
	if _, err := s.OpenPaddedReader(masterKey, bytes.NewReader(plain.Bytes())); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("plain stream: err = %v, want ErrStreamAuth", err)
	}

	// authenticates as padded, but carries no frame
	noFrame := sealAsPadded(t, s, masterKey, notAFrame(t, 512), nil)
	if _, err := s.OpenPaddedReader(masterKey, bytes.NewReader(noFrame)); !errors.Is(err, ErrNoPaddingFrame) {
		t.Errorf("no frame: err = %v, want ErrNoPaddingFrame", err)
	}

	// too short to hold a frame at all
	short := sealAsPadded(t, s, masterKey, []byte{paddingVersion, 0, 0}, nil)
	if _, err := s.OpenPaddedReader(masterKey, bytes.NewReader(short)); !errors.Is(err, ErrNoPaddingFrame) {
		t.Errorf("truncated frame: err = %v, want ErrNoPaddingFrame", err)
	}

	// a declared length that does not fit in an int64, rejected on the guard
	huge := make([]byte, paddingFrameSize)
	huge[0] = paddingVersion
	binary.BigEndian.PutUint64(huge[1:], math.MaxUint64)
	if _, err := s.OpenPaddedReader(masterKey, bytes.NewReader(sealAsPadded(t, s, masterKey, huge, nil))); !errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("oversized length: err = %v, want ErrPaddingMalformed", err)
	}
}

func TestPaddedReaderErrorsAreSticky(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// a frame promising a megabyte the stream does not hold
	frame := make([]byte, paddingFrameSize)
	frame[0] = paddingVersion
	binary.BigEndian.PutUint64(frame[1:], 1<<20)
	r, err := s.OpenPaddedReader(masterKey, bytes.NewReader(sealAsPadded(t, s, masterKey, frame, nil)))
	if err != nil {
		t.Fatalf("OpenPaddedReader error: %v", err)
	}

	_, first := r.Read(make([]byte, 64))
	if !errors.Is(first, ErrPaddingMalformed) {
		t.Fatalf("err = %v, want ErrPaddingMalformed", first)
	}
	for i := range 3 {
		if _, err := r.Read(make([]byte, 64)); err != first {
			t.Errorf("retry %d: err = %v, want the identical sticky error", i, err)
		}
	}
	if _, err := r.WriteTo(io.Discard); err != first {
		t.Errorf("WriteTo after the failure: err = %v, want the identical sticky error", err)
	}
	if err := r.Close(); err != first {
		t.Errorf("Close after the failure: err = %v, want the identical sticky error", err)
	}
}

func TestPaddedReaderZeroLengthReadIsNoOp(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, 512)

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	r, err := s.OpenPaddedReader(masterKey, &sealed)
	if err != nil {
		t.Fatalf("OpenPaddedReader error: %v", err)
	}

	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	got := make([]byte, r.Size())
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("ReadFull error: %v", err)
	}
	// the payload is spent, but a read of nothing must not stand in for the
	// drain that ends the stream
	if n, err := r.Read([]byte{}); n != 0 || err != nil {
		t.Errorf("Read(empty) at the payload end = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := r.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("Read at the payload end = (%d, %v), want (0, io.EOF)", n, err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("round-tripped payload differs")
	}
}

// TestPaddedReaderMixedReadAndWriteTo covers the shape a handler ends up with:
// peek at the head of the payload, then hand the rest to io.Copy.
func TestPaddedReaderMixedReadAndWriteTo(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)

	var sealed bytes.Buffer
	if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	r, err := s.OpenPaddedReader(masterKey, &sealed)
	if err != nil {
		t.Fatalf("OpenPaddedReader error: %v", err)
	}

	head := make([]byte, 300)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatalf("ReadFull error: %v", err)
	}
	var rest bytes.Buffer
	n, err := r.WriteTo(&rest)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if want := int64(len(payload) - len(head)); n != want {
		t.Errorf("WriteTo = %d, want the remaining %d", n, want)
	}
	if !bytes.Equal(append(head, rest.Bytes()...), payload) {
		t.Error("payload differs after a mixed read")
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close after a complete read: %v", err)
	}
}

// failingSource hands out its data and then fails instead of reporting EOF,
// the way a network source dies mid-stream. It is the only way to reach the
// paths where the reader passes an I/O error through rather than translating
// it into a format error.
type failingSource struct {
	data []byte
	off  int
	err  error
}

func (f *failingSource) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, f.err
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

// sealPaddedBlob seals payload with padding and returns the blob, the chunk
// count and the plaintext offset where the padding starts, so a test can aim a
// bit flip at the payload or at the padding.
func sealPaddedBlob(t *testing.T, s *Scheme, masterKey, payload []byte) []byte {
	t.Helper()
	var sealed bytes.Buffer
	if _, err := s.SealPaddedStream(masterKey, &sealed, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("SealPaddedStream error: %v", err)
	}
	return sealed.Bytes()
}

// chunkOffset is where chunk i starts in a sealed stream.
func chunkOffset(i int) int { return streamHeaderSize + i*(testChunkSize+TagSize) }

// TestPaddedReaderSurfacesStreamFailures covers the two places a chunk can fail
// to authenticate once the frame has been read: under the payload, and under
// the padding, where only the drain is looking.
func TestPaddedReaderSurfacesStreamFailures(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)
	blob := sealPaddedBlob(t, s, masterKey, payload)

	// the padding starts inside this chunk, so the last one is padding only
	padStart := int(paddedTestSize+paddingFrameSize) / testChunkSize
	lastChunk := (len(blob) - streamHeaderSize) / (testChunkSize + TagSize)
	if padStart >= lastChunk {
		t.Fatalf("padding starts in chunk %d of %d, need a padding-only chunk", padStart, lastChunk)
	}

	tamper := func(chunk int) []byte {
		cut := append([]byte{}, blob...)
		cut[chunkOffset(chunk)+10] ^= 0xFF
		return cut
	}

	tests := []struct {
		name  string
		chunk int
	}{
		{name: "underThePayload", chunk: 1},
		{name: "underThePadding", chunk: lastChunk - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// through Read, which is where a pulling caller meets it
			r, err := s.OpenPaddedReader(masterKey, bytes.NewReader(tamper(tt.chunk)))
			if err != nil {
				t.Fatalf("OpenPaddedReader error: %v", err)
			}
			_, err = io.Copy(io.Discard, struct{ io.Reader }{r}) // hide WriteTo
			if !errors.Is(err, ErrStreamAuth) {
				t.Errorf("Read: err = %v, want ErrStreamAuth", err)
			}
			if closeErr := r.Close(); !errors.Is(closeErr, ErrStreamAuth) {
				t.Errorf("Close: err = %v, want the sticky ErrStreamAuth", closeErr)
			}

			// and through WriteTo, the io.Copy fast path
			r, err = s.OpenPaddedReader(masterKey, bytes.NewReader(tamper(tt.chunk)))
			if err != nil {
				t.Fatalf("OpenPaddedReader error: %v", err)
			}
			if _, err := r.WriteTo(io.Discard); !errors.Is(err, ErrStreamAuth) {
				t.Errorf("WriteTo: err = %v, want ErrStreamAuth", err)
			}
		})
	}
}

// TestPaddedReaderPassesSourceErrorsThrough pins that an I/O failure stays
// itself instead of being reported as a malformed stream: the frame read on the
// way in, and the drain on the way out.
func TestPaddedReaderPassesSourceErrorsThrough(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, paddedTestSize)
	blob := sealPaddedBlob(t, s, masterKey, payload)
	sentinel := errors.New("disk fell over")

	// dies while the constructor is reading the frame out of chunk 0
	_, err := s.OpenPaddedReader(masterKey, &failingSource{data: blob[:streamHeaderSize+10], err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Errorf("frame read: err = %v, want the source error", err)
	}
	if errors.Is(err, ErrNotPadded) {
		t.Errorf("err = %v, want an I/O failure, not a format verdict", err)
	}

	// dies at the very end, where only the drain and the end probe are looking
	r, err := s.OpenPaddedReader(masterKey, &failingSource{data: blob, err: sentinel})
	if err != nil {
		t.Fatalf("OpenPaddedReader error: %v", err)
	}
	if _, err := r.WriteTo(io.Discard); !errors.Is(err, sentinel) {
		t.Errorf("drain: err = %v, want the source error", err)
	}
}

// TestPaddedReaderRejectsUnpaddableLength covers the frame whose length is a
// legal int64 that PaddedSize still cannot frame, which is the guard between
// the MaxUint64 check and the subtraction that computes the padding.
func TestPaddedReaderRejectsUnpaddableLength(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	frame := make([]byte, paddingFrameSize)
	frame[0] = paddingVersion
	binary.BigEndian.PutUint64(frame[1:], math.MaxInt64)
	_, err := s.OpenPaddedReader(masterKey, bytes.NewReader(sealAsPadded(t, s, masterKey, frame, nil)))
	if !errors.Is(err, ErrPaddingMalformed) {
		t.Errorf("err = %v, want ErrPaddingMalformed", err)
	}
}

func TestPaddedReaderIsSpentAfterACleanEnd(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	payload := randomData(t, 2048)

	r, err := s.OpenPaddedReader(masterKey, bytes.NewReader(sealPaddedBlob(t, s, masterKey, payload)))
	if err != nil {
		t.Fatalf("OpenPaddedReader error: %v", err)
	}
	var out bytes.Buffer
	if _, err := r.WriteTo(&out); err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Error("round-tripped payload differs")
	}

	// a spent reader is empty, not broken: nothing is left to hand out, and the
	// stream behind it already authenticated
	if n, err := r.WriteTo(&out); n != 0 || err != nil {
		t.Errorf("WriteTo after the end = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := r.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("Read after the end = (%d, %v), want (0, io.EOF)", n, err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close after the end = %v, want nil", err)
	}
}
