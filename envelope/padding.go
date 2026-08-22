package envelope

// Length hiding for the streaming API.
//
// A sealed stream reveals the exact plaintext length: the header states the
// chunk size in the clear, so an observer recovers
// n = size - streamHeaderSize - TagSize*chunks from the file size alone. That
// is enough to identify a known document by its byte count or to watch a file
// grow across saves. The helpers here remove the low bits of that number by
// padding the payload before it is sealed.
//
// The padding lives inside the sealed plaintext, so it is encrypted and
// authenticated like everything else. Nothing about the on-the-wire stream
// changes: the file still starts with the ordinary streamVersion (0x81)
// header, and the frame below is what those chunks encrypt.
//
//	on disk:   0x81 || saltLen || salt || chunkSize || noncePrefix || chunk...
//	                                                       │
//	                                    the chunks decrypt to ▼
//	plaintext: 0x01 || realLen(8, big-endian) || payload || zero padding
//
// So paddingVersion (0x01) and streamVersion (0x81) never meet: the first is
// the leading plaintext byte, visible only after decryption, and the second is
// the leading file byte. paddingVersion shares its value with envelopeVersion
// for the same reason, harmlessly, since the two are read from different
// places. realLen is a fixed 8-byte big-endian uint64, wide enough for any
// int64 file size and the same width and byte order the rest of the package
// uses (see the stream chunk counter and SealInt64); fixed width also keeps
// the frame length constant, so it cannot itself hint at the payload size.
//
// All the padding sits at the tail. Every chunk but the last is already
// exactly chunkSize bytes of plaintext by construction, so interior chunks
// carry no length information.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"os"
)

const (
	// paddingVersion tags the padded frame so a stream that authenticates but
	// does not carry a padded payload is rejected explicitly. It is the first
	// byte of the sealed *plaintext*, not of the file: the file still begins
	// with streamVersion (0x81). Sharing a value with envelopeVersion is
	// therefore harmless, since the two are never read from the same place.
	paddingVersion byte = 0x01

	// paddingFrameSize is the frame that precedes the payload inside the
	// sealed plaintext: version(1) || realLen(8, big-endian).
	paddingFrameSize = 9
)

// Errors returned by the padded helpers.
var (
	// ErrNotPadded is returned when a stream authenticates but its plaintext
	// is not the frame written by [Scheme.SealPaddedFile], for example a
	// stream sealed by [Scheme.SealFile].
	ErrNotPadded = errors.New("envelope: sealed stream carries no padded payload")

	// ErrSourceSize is returned when the source is not a regular file, or when
	// its size changed while it was being sealed. Padding is computed from the
	// size up front, so a source that moves underneath the sealer cannot
	// produce a well-formed padded stream.
	ErrSourceSize = errors.New("envelope: source must be a regular file of stable size")
)

// PaddedSize reports the padded plaintext length [Scheme.SealPaddedFile] uses
// for a payload of n bytes: the 9-byte frame plus n, rounded up by the Padmé
// rule (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files",
// PoPETs 2019). Padmé keeps only the top log2(log2(L)) bits of the length
// significant, which caps the overhead near 12% and leaves it around 3% on
// average, while collapsing every length inside one bucket onto a single
// on-disk size.
//
// The resulting file is streamHeaderSize + PaddedSize(n) + TagSize*chunks
// bytes, with chunks = ceil(PaddedSize(n)/chunkSize). It returns 0 for a
// negative n, or for an n so large that the frame cannot be added.
func PaddedSize(n int64) int64 {
	if n < 0 || n > math.MaxInt64-paddingFrameSize {
		return 0
	}
	return padme(n + paddingFrameSize)
}

// padme rounds l up so that only its top log2(log2(l)) bits are significant.
// The bucket width at length l is 2^(floor(log2 l) - floor(log2 log2 l) - 1),
// so the padding is proportional to the length instead of a fixed block size.
func padme(l int64) int64 {
	if l < 4 {
		return l
	}

	// l >= 4 here, so both conversions are of a positive value and the
	// exponents below are at least 2 and 1 respectively.
	e := bits.Len64(uint64(l)) - 1 // #nosec G115 -- floor(log2 l)
	s := bits.Len64(uint64(e))     // #nosec G115 -- floor(log2 e) + 1
	z := e - s
	if z < 1 {
		return l
	}

	mask := int64(1)<<z - 1
	if l > math.MaxInt64-mask {
		// rounding would overflow; leave an absurd length unpadded rather
		// than wrapping around to a shorter one.
		return l
	}
	return (l + mask) &^ mask
}

// zeroReader is an endless source of zero bytes. The padding is XORed with the
// keystream like any other plaintext, so zeros are indistinguishable from real
// data once sealed and cost nothing to produce.
type zeroReader struct{}

// Read fills p with zeros and never fails.
func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// SealPaddedFile seals srcPath into a newly created dstPath, padding the
// payload so the file size no longer reveals the exact plaintext length. It is
// shorthand for [Scheme.SealPaddedFileAAD] with a nil AAD.
func (s *Scheme) SealPaddedFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.SealPaddedFileAAD(masterKey, dstPath, srcPath, nil)
}

// SealPaddedFileAAD seals srcPath into a newly created dstPath with the
// payload padded to [PaddedSize], binding aad into every chunk, and returns
// the number of real payload bytes sealed (not the padded length). Like
// [Scheme.SealFileAAD] it streams chunk by chunk and refuses to overwrite an
// existing destination.
//
// Only the length is hidden, and only to within one Padmé bucket. Everything
// the filesystem records around the file, above all its name, leaks
// independently: give sealed files opaque names (see [RandomHex]) if that
// matters.
func (s *Scheme) SealPaddedFileAAD(masterKey []byte, dstPath, srcPath string, aad []byte) (int64, error) {
	return pipeFile(dstPath, srcPath, func(dst io.Writer, src *os.File) (int64, error) {
		info, err := src.Stat()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			// a pipe or device has no meaningful size to pad against.
			return 0, ErrSourceSize
		}
		return s.sealPaddedStream(masterKey, dst, src, info.Size(), aad)
	})
}

// OpenPaddedFile opens a file sealed by [Scheme.SealPaddedFile] into a newly
// created dstPath, discarding the padding. It is shorthand for
// [Scheme.OpenPaddedFileAAD] with a nil AAD.
func (s *Scheme) OpenPaddedFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.OpenPaddedFileAAD(masterKey, dstPath, srcPath, nil)
}

// OpenPaddedFileAAD opens a file sealed by [Scheme.SealPaddedFileAAD] into a
// newly created dstPath, verifying aad, and returns the number of payload
// bytes recovered. The padding is read and authenticated but not written out.
//
// A stream that authenticates but was not sealed with padding fails with
// [ErrNotPadded].
func (s *Scheme) OpenPaddedFileAAD(masterKey []byte, dstPath, srcPath string, aad []byte) (int64, error) {
	return pipeFile(dstPath, srcPath, func(dst io.Writer, src *os.File) (int64, error) {
		return s.openPaddedStream(masterKey, dst, src, aad)
	})
}

// sealPaddedStream frames size bytes read from src, appends zero padding out
// to [PaddedSize] and seals the result as one stream.
func (s *Scheme) sealPaddedStream(masterKey []byte, dst io.Writer, src io.Reader, size int64, aad []byte) (int64, error) {
	target := PaddedSize(size)
	if target == 0 {
		return 0, ErrSourceSize
	}

	var frame [paddingFrameSize]byte
	frame[0] = paddingVersion
	// size is non-negative (PaddedSize rejected anything else), so the
	// conversion is the plain two's-complement round-trip read back below.
	binary.BigEndian.PutUint64(frame[1:], uint64(size)) // #nosec G115

	padded := io.MultiReader(
		bytes.NewReader(frame[:]),
		src,
		io.LimitReader(zeroReader{}, target-paddingFrameSize-size),
	)

	n, err := s.SealStreamAAD(masterKey, dst, padded, aad)
	if err != nil {
		return n, err
	}
	if n != target {
		// src delivered more or fewer bytes than Stat promised, so the frame
		// no longer describes the payload. pipeFile removes the destination.
		return n, ErrSourceSize
	}
	return size, nil
}

// openPaddedStream reads the frame, copies the payload and then drains the
// padding.
func (s *Scheme) openPaddedStream(masterKey []byte, dst io.Writer, src io.Reader, aad []byte) (int64, error) {
	r, err := s.OpenReaderAAD(masterKey, src, aad)
	if err != nil {
		return 0, err
	}

	var frame [paddingFrameSize]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, ErrNotPadded
		}
		return 0, err
	}
	if frame[0] != paddingVersion {
		return 0, ErrNotPadded
	}
	size := binary.BigEndian.Uint64(frame[1:])
	if size > math.MaxInt64 {
		return 0, ErrNotPadded
	}

	written, err := io.CopyN(dst, r, int64(size)) // #nosec G115 -- bounded above
	if err != nil {
		if errors.Is(err, io.EOF) {
			// the frame claims more payload than the stream holds.
			return written, ErrNotPadded
		}
		return written, err
	}

	// Draining is not optional: the padding occupies whole trailing chunks,
	// and only reading to the end authenticates them and the final-chunk flag.
	// Stopping at the payload would accept a stream truncated inside its
	// padding.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return written, err
	}
	return written, nil
}
