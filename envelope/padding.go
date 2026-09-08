package envelope

// Length hiding for the streaming API.
//
// A sealed stream gives its plaintext length away: the chunk size is in the
// clear, so the file size alone yields it. These helpers pad the payload before
// sealing. The padding sits inside the sealed plaintext, so the file on disk
// still looks like an ordinary stream:
//
//	on disk:   0x81 || saltLen || salt || chunkSize || noncePrefix || chunk...
//	                                                       │
//	                                    the chunks decrypt to ▼
//	plaintext: 0x01 || realLen(8, big-endian) || payload || zero padding
//
// paddingVersion (0x01) is the first plaintext byte and streamVersion (0x81)
// the first file byte, so the two never meet. All padding goes at the tail:
// every chunk but the last is already exactly chunkSize bytes.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
)

const (
	// first byte of the sealed plaintext, not of the file
	paddingVersion byte = 0x01

	// frame in front of the payload: version(1) || realLen(8, big-endian)
	paddingFrameSize = 9
)

// paddedStreamTag, authenticated into every chunk by streamAuthData (see
// stream.go), keeps the padded format apart from the plain one, so neither
// reader accepts the other's stream. It is a parameter of sealStream and
// openReader, never part of the caller's aad, and it is hashed rather than
// stored, so both formats write the same header and a file never shows that it
// is padded.

// Errors from the padded helpers. ErrNotPadded and ErrSourceSize are
// umbrellas: match them to catch a class, the sentinels to branch on a case.
var (
	// ErrNotPadded means a stream could not be read as a padded one.
	ErrNotPadded = errors.New("envelope: not a readable padded stream")

	// ErrNoPaddingFrame means the stream authenticated as padded but carries no
	// frame, which today means a padded format newer than this reader.
	ErrNoPaddingFrame = fmt.Errorf("%w: no padding frame", ErrNotPadded)

	// ErrPaddingMalformed means the frame was read and the stream contradicts
	// it: too little payload, a padding length PaddedSize would not produce, or
	// padding that is not zeros. A stream simply cut short gives [ErrStreamAuth]
	// instead.
	ErrPaddingMalformed = fmt.Errorf("%w: frame contradicts the payload it describes", ErrNotPadded)

	// ErrSourceSize means a source could not supply the byte count the padding
	// was computed for.
	ErrSourceSize = errors.New("envelope: source size is not usable for padding")

	// ErrSourceIrregular means a [Scheme.SealPaddedFile] source is not a
	// regular file, so it has no size to pad against.
	ErrSourceIrregular = fmt.Errorf("%w: source is not a regular file", ErrSourceSize)

	// ErrSourceShort and ErrSourceLong say which way the source missed. Spotting
	// extra data costs one byte of src that cannot be put back, so frame a
	// payload inside a longer stream with io.LimitReader.
	ErrSourceShort = fmt.Errorf("%w: source ended before the declared size", ErrSourceSize)
	ErrSourceLong  = fmt.Errorf("%w: source holds more data than the declared size (one byte consumed)", ErrSourceSize)

	// ErrIncompleteRead means a [PaddedReader] was closed with payload still
	// unread, so the padding was never drained and the end is unverified.
	ErrIncompleteRead = errors.New("envelope: padded reader closed before its payload was read")

	// errPaddingInvariant: a sealer post-condition failed. No source can cause
	// it, so it is not an ErrSource* value that would blame the caller.
	errPaddingInvariant = errors.New("envelope: padded sealer post-condition failed")
)

// PaddedSize reports the padded plaintext length for an n-byte payload: the
// 9-byte frame plus n, rounded up by Padmé (Nikitin et al., "Reducing Metadata
// Leakage from Encrypted Files", PoPETs 2019), which caps overhead near 12%.
// The sealed file is then streamHeaderSize + PaddedSize(n) + TagSize*chunks
// bytes, chunks = ceil(PaddedSize(n)/chunkSize). Returns 0 if n is negative or
// too large to frame.
func PaddedSize(n int64) int64 {
	if n < 0 || n > math.MaxInt64-paddingFrameSize {
		return 0
	}
	return padme(n + paddingFrameSize)
}

// padme rounds l up so only its top log2(log2(l)) bits matter.
//
// Frozen for paddingVersion 0x01: the opener checks drained padding against
// PaddedSize, so a new rule would not reinterpret old files, it would make
// every one of them unreadable. It needs a new paddingVersion and an opener
// that dispatches on it.
func padme(l int64) int64 {
	if l < 4 {
		return l
	}

	// l >= 4, so both conversions take a positive value.
	e := bits.Len64(uint64(l)) - 1 // #nosec G115 -- floor(log2 l)
	s := bits.Len64(uint64(e))     // #nosec G115 -- floor(log2 e) + 1
	z := e - s
	if z < 1 {
		return l
	}

	mask := int64(1)<<z - 1
	if l > math.MaxInt64-mask {
		// leave an absurd length unpadded rather than wrapping it shorter
		return l
	}
	return (l + mask) &^ mask
}

// SealPaddedFile seals srcPath into a newly created dstPath, padding the
// payload so the file size no longer reveals the plaintext length. It is
// shorthand for [Scheme.SealPaddedFileAAD] with a nil AAD.
func (s *Scheme) SealPaddedFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.SealPaddedFileAAD(masterKey, dstPath, srcPath, nil)
}

// SealPaddedFileAAD seals srcPath into a newly created dstPath, padding the
// payload to [PaddedSize] and binding aad into every chunk, and returns the
// real payload length. It will not overwrite an existing destination.
//
// Only the length is hidden, and only to within one Padmé bucket; names,
// timestamps and access patterns leak on their own.
func (s *Scheme) SealPaddedFileAAD(masterKey []byte, dstPath, srcPath string, aad []byte) (int64, error) {
	return pipeFile(dstPath, srcPath, func(dst io.Writer, src *os.File) (int64, error) {
		info, err := src.Stat()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, ErrSourceIrregular
		}
		return s.SealPaddedStreamAAD(masterKey, dst, src, info.Size(), aad)
	})
}

// OpenPaddedFile opens a file sealed by [Scheme.SealPaddedFile] into a newly
// created dstPath, discarding the padding. It is shorthand for
// [Scheme.OpenPaddedFileAAD] with a nil AAD.
func (s *Scheme) OpenPaddedFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.OpenPaddedFileAAD(masterKey, dstPath, srcPath, nil)
}

// OpenPaddedFileAAD opens a file sealed by [Scheme.SealPaddedFileAAD] into a
// newly created dstPath, verifying aad, and returns the payload length. The
// padding is authenticated but not written out; failures are
// [ErrNoPaddingFrame] or [ErrPaddingMalformed]. Unlike the stream form, this
// one removes a partial dst on error.
func (s *Scheme) OpenPaddedFileAAD(masterKey []byte, dstPath, srcPath string, aad []byte) (int64, error) {
	return pipeFile(dstPath, srcPath, func(dst io.Writer, src *os.File) (int64, error) {
		return s.OpenPaddedStreamAAD(masterKey, dst, src, aad)
	})
}

// SealPaddedStream seals size bytes read from src to dst with the payload
// padded to [PaddedSize]. It is shorthand for [Scheme.SealPaddedStreamAAD]
// with a nil AAD.
func (s *Scheme) SealPaddedStream(masterKey []byte, dst io.Writer, src io.Reader, size int64) (int64, error) {
	return s.SealPaddedStreamAAD(masterKey, dst, src, size, nil)
}

// SealPaddedStreamAAD reads size bytes from src, pads them to [PaddedSize] and
// seals the result to dst as one stream, binding aad into every chunk. It
// returns the real payload length. Padding is generated as the sealer asks for
// it, so nothing is staged on disk.
//
// size must match what src delivers, since the padded length is fixed before
// the first chunk is sealed. A source that misses it fails with
// [ErrSourceShort] or [ErrSourceLong] before any padding is written, which is
// what makes size safe to take from an untrusted peer; dst is then left with a
// partial stream for the caller to discard.
//
// Only [Scheme.OpenPaddedStreamAAD] reads this back, never
// [Scheme.OpenStreamAAD].
func (s *Scheme) SealPaddedStreamAAD(masterKey []byte, dst io.Writer, src io.Reader, size int64, aad []byte) (int64, error) {
	target := PaddedSize(size)
	if target == 0 {
		return 0, ErrSourceSize
	}

	var frame [paddingFrameSize]byte
	frame[0] = paddingVersion
	// size >= 0, since PaddedSize rejected anything else
	binary.BigEndian.PutUint64(frame[1:], uint64(size)) // #nosec G115

	payload := &exactReader{r: src, left: size}
	padded := io.MultiReader(
		bytes.NewReader(frame[:]),
		payload,
		io.LimitReader(zeroReader{}, target-paddingFrameSize-size),
	)

	n, err := s.sealStream(masterKey, dst, padded, paddedStreamTag, aad)
	if err != nil {
		return n, err
	}
	if !payload.reachedEnd() {
		// nothing read src to its end, so trailing data was never checked
		return n, errPaddingInvariant
	}
	if n != target {
		// backstop: the frame or padding arithmetic is wrong
		return n, errPaddingInvariant
	}
	return size, nil
}

// PaddedReader pulls the payload out of a stream sealed by
// [Scheme.SealPaddedStreamAAD] and throws the padding away. Use it when you
// want the payload length up front: a handler can set Content-Length from
// [PaddedReader.Size] before writing any body.
//
// The payload ends before the stream does, and the padding behind it still has
// to be authenticated, so nothing you read is trustworthy until you reach the
// end: read to [io.EOF], take a nil error from [PaddedReader.WriteTo], or call
// [PaddedReader.Close]. Errors are sticky, and a PaddedReader is not safe for
// concurrent use.
type PaddedReader struct {
	r    *StreamReader // the plain stream whose plaintext carries the frame
	size int64         // payload length from the frame, already authenticated
	left int64         // payload bytes not yet handed out
	pad  int64         // padding bytes still to drain, per PaddedSize
	err  error         // sticky: the first failure, or io.EOF after a clean end
}

// OpenPaddedReader returns a [PaddedReader] over src. It is shorthand for
// [Scheme.OpenPaddedReaderAAD] with a nil AAD.
func (s *Scheme) OpenPaddedReader(masterKey []byte, src io.Reader) (*PaddedReader, error) {
	return s.OpenPaddedReaderAAD(masterKey, src, nil)
}

// OpenPaddedReaderAAD returns a [PaddedReader] over src, verifying aad. Header
// and frame are both checked here, so a stream that is not a readable padded
// one is reported before any payload byte, and [PaddedReader.Size] is known
// from the start.
//
// The frame is authenticated, but that says nothing about the rest of the
// stream: truncation shows up later as [ErrStreamAuth], while
// [ErrPaddingMalformed] means a stream that authenticates whole and still
// disagrees with its own frame. A plain [Scheme.SealStream] blob fails here as
// [ErrStreamAuth], the same as a wrong key; retry with [Scheme.OpenReaderAAD]
// over a fresh reader to tell them apart.
func (s *Scheme) OpenPaddedReaderAAD(masterKey []byte, src io.Reader, aad []byte) (*PaddedReader, error) {
	r, err := s.openReader(masterKey, src, paddedStreamTag, aad)
	if err != nil {
		return nil, err
	}

	// every exit below drops a StreamReader holding decrypted chunk 0; fail wipes it
	fail := func(err error) (*PaddedReader, error) {
		r.fail(err)
		return nil, err
	}

	var frame [paddingFrameSize]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fail(ErrNoPaddingFrame)
		}
		return fail(err)
	}
	if frame[0] != paddingVersion {
		return fail(ErrNoPaddingFrame)
	}
	size := binary.BigEndian.Uint64(frame[1:])
	if size > math.MaxInt64 {
		return fail(ErrPaddingMalformed)
	}
	n := int64(size) // #nosec G115 -- bounded above

	// Padding the sealer must have written. Knowing it up front bounds the
	// drain, so a frame claiming a tiny payload inside a huge stream is
	// rejected early. padme never shrinks a length, so this cannot go negative.
	want := PaddedSize(n)
	if want == 0 {
		return fail(ErrPaddingMalformed)
	}

	return &PaddedReader{r: r, size: n, left: n, pad: want - paddingFrameSize - n}, nil
}

// Size is the payload length from the stream's authenticated frame, known
// before any payload byte is read. The frame is authentic, but the stream
// behind it can still end early, with [ErrStreamAuth] or [ErrPaddingMalformed].
func (r *PaddedReader) Size() int64 { return r.size }

// Read hands out the payload and never the padding. It returns [io.EOF] only
// after the padding has been drained and checked, so a clean EOF means the
// whole stream authenticated.
func (r *PaddedReader) Read(p []byte) (int, error) {
	// before the empty-p case, so a finished reader answers every call alike
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		// don't fall through to finish on a call that asked for nothing
		return 0, nil
	}
	if r.left == 0 {
		if err := r.finish(); err != nil {
			r.fail(err)
			return 0, r.err
		}
		r.fail(io.EOF)
		return 0, r.err
	}

	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.r.Read(p)
	r.left -= int64(n)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// the frame claims more payload than the stream holds
			r.fail(ErrPaddingMalformed)
		} else {
			r.fail(err)
		}
		return n, r.err
	}
	return n, nil
}

// WriteTo drains the payload into dst, which is what [io.Copy] picks up, then
// authenticates the padding. A nil error means dst holds the whole payload and
// the stream ended cleanly. Chunks reach dst as they authenticate, so treat dst
// as provisional until then.
func (r *PaddedReader) WriteTo(dst io.Writer) (int64, error) {
	if r.err != nil {
		if errors.Is(r.err, io.EOF) {
			return 0, nil
		}
		return 0, r.err
	}

	written, err := io.CopyN(dst, r.r, r.left)
	r.left -= written
	if err != nil {
		if errors.Is(err, io.EOF) {
			// the frame claims more payload than the stream holds
			r.fail(ErrPaddingMalformed)
		} else {
			// A failing dst ends the reader too: the padding cannot be
			// authenticated without reading a payload nobody wants.
			r.fail(err)
		}
		return written, r.err
	}
	if err := r.finish(); err != nil {
		r.fail(err)
		return written, r.err
	}
	r.fail(io.EOF)
	return written, nil
}

// Close ends the reader and reports whether what it produced was authentic: nil
// means the payload was complete and the padding authenticated. It reads at
// most the padding and never closes the underlying source.
//
// It is for the caller who reads [PaddedReader.Size] bytes and stops, one call
// short of the padding check. Closing with payload still unread returns
// [ErrIncompleteRead] rather than draining what was skipped.
func (r *PaddedReader) Close() error {
	switch {
	case r.err != nil:
		if errors.Is(r.err, io.EOF) {
			return nil
		}
		return r.err
	case r.left > 0:
		r.fail(ErrIncompleteRead)
		return r.err
	}

	if err := r.finish(); err != nil {
		r.fail(err)
		return r.err
	}
	r.fail(io.EOF)
	return nil
}

// finish reads exactly the padding the frame calls for, checks it is zeros, and
// requires the stream to end there. The padding fills whole trailing chunks, so
// reading it is what authenticates them and the final-chunk flag; checking the
// zeros keeps the padding from being somewhere to hide data.
func (r *PaddedReader) finish() error {
	// one buffer for the whole drain, well under MinChunkSize
	var scratch [512]byte
	for left := r.pad; left > 0; {
		n := int64(len(scratch))
		if n > left {
			n = left
		}
		if _, err := io.ReadFull(r.r, scratch[:n]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return ErrPaddingMalformed
			}
			return err
		}
		for _, b := range scratch[:n] {
			if b != 0 {
				return ErrPaddingMalformed
			}
		}
		left -= n
	}
	r.pad = 0

	// Padding ended where PaddedSize says, so the stream must end here too.
	// This read also authenticates the final-chunk flag.
	var probe [1]byte
	switch n, err := io.ReadFull(r.r, probe[:]); {
	case n > 0:
		return ErrPaddingMalformed
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

// fail records the terminal state, so every later call answers alike, and ends
// the stream underneath, wiping the plaintext chunk it still holds. Only the
// first call counts.
func (r *PaddedReader) fail(err error) {
	if r.err == nil {
		r.err = err
		r.r.fail(err)
	}
}

// OpenPaddedStream opens a padded stream from src into dst, discarding the
// padding. It is shorthand for [Scheme.OpenPaddedStreamAAD] with a nil AAD.
func (s *Scheme) OpenPaddedStream(masterKey []byte, dst io.Writer, src io.Reader) (int64, error) {
	return s.OpenPaddedStreamAAD(masterKey, dst, src, nil)
}

// OpenPaddedStreamAAD opens a stream sealed by [Scheme.SealPaddedStreamAAD]
// into dst, verifying aad, and returns the payload bytes written. It is
// [Scheme.OpenPaddedReaderAAD] driven to the end.
//
// Payload reaches dst before the trailing padding is authenticated, so treat
// dst as provisional until this returns nil. A plain [Scheme.SealStream] blob
// fails here as [ErrStreamAuth], the same as a wrong key; retry with
// [Scheme.OpenStreamAAD] over a fresh reader to tell them apart.
//
// Use [Scheme.OpenPaddedReaderAAD] when the payload length is wanted before the
// body is written.
func (s *Scheme) OpenPaddedStreamAAD(masterKey []byte, dst io.Writer, src io.Reader, aad []byte) (int64, error) {
	r, err := s.OpenPaddedReaderAAD(masterKey, src, aad)
	if err != nil {
		return 0, err
	}
	return r.WriteTo(dst)
}
