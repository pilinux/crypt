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
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
)

const (
	// paddingVersion is the first byte of the sealed plaintext, not of the
	// file, so sharing a value with envelopeVersion is harmless.
	paddingVersion byte = 0x01

	// paddingFrameSize is the frame that precedes the payload inside the
	// sealed plaintext: version(1) || realLen(8, big-endian).
	paddingFrameSize = 9

	// maxConsecutiveEmptyReads is how often a source may answer "no bytes, no
	// error" before we stop waiting on it. That reply is legal, so the first few
	// are retried; a source that only ever replies so is legal too, and would
	// spin a core. The bound and io.ErrNoProgress come from bufio, so a reader
	// the rest of Go tolerates is tolerated here.
	maxConsecutiveEmptyReads = 100
)

// The padded format is kept apart from the plain one by paddedStreamTag, which
// every chunk authenticates through streamAuthData (see stream.go). Neither
// reader accepts the other's stream, and because the tag is hashed rather than
// stored, both formats still write the identical header and a file does not
// advertise whether it is padded.
//
// The tag reaches the AEAD as a parameter of the unexported sealStream and
// openReader, not through the caller's aad. That is deliberate: aad belongs to
// the caller, so anything smuggled into it is something the caller of the other
// format can type out, and the separation would hold only for callers who
// happened not to. Format identity and record identity are different things and
// travel in different arguments.
//
// The tag carries a version because it is frozen the way the HKDF labels are;
// the padded format's own version byte is paddingVersion, inside the
// authenticated plaintext, which is what a future format would dispatch on.

// Errors returned by the padded helpers. The two umbrellas, ErrNotPadded and
// ErrSourceSize, carry no cause of their own so the sentinels wrapping them
// read correctly when concatenated; match the umbrella to catch a class, the
// sentinel to branch on a case.
var (
	// ErrNotPadded means a stream could not be read as a padded one.
	ErrNotPadded = errors.New("envelope: not a readable padded stream")

	// ErrNoPaddingFrame means a stream authenticated as padded but its plaintext
	// holds no frame: too short for one, or a first byte that is not
	// paddingVersion. Since the AAD is domain-separated, an ordinary
	// [Scheme.SealStream] blob never gets this far; the live case is a padded
	// format newer than this reader, which authenticates and is then rejected
	// on its version byte.
	ErrNoPaddingFrame = fmt.Errorf("%w: no padding frame", ErrNotPadded)

	// ErrPaddingMalformed means a frame was read and the stream then
	// contradicted it: too little payload, or a padding length PaddedSize would
	// not have produced. Unlike ErrNoPaddingFrame the stream does claim to be
	// padded, so this is a broken file rather than an unpadded one.
	ErrPaddingMalformed = fmt.Errorf("%w: frame contradicts the payload it describes", ErrNotPadded)

	// ErrSourceSize means a source could not supply the byte count the padding
	// was computed for. Returned bare when the count itself is unusable, and
	// wrapped by the sentinels below for the reasons a source can miss it.
	ErrSourceSize = errors.New("envelope: source size is not usable for padding")

	// ErrSourceIrregular means a [Scheme.SealPaddedFile] source is not a
	// regular file, so it has no size to pad against.
	ErrSourceIrregular = fmt.Errorf("%w: source is not a regular file", ErrSourceSize)

	// ErrSourceShort and ErrSourceLong say which way the source missed. Branch
	// on them when the direction drives the response, since a truncated upload
	// is worth retrying and an overlong one is not. Detecting extra data costs
	// one byte of src that cannot be pushed back, so frame a payload inside a
	// longer stream with io.LimitReader.
	ErrSourceShort = fmt.Errorf("%w: source ended before the declared size", ErrSourceSize)
	ErrSourceLong  = fmt.Errorf("%w: source holds more data than the declared size (one byte consumed)", ErrSourceSize)

	// ErrIncompleteRead means a [PaddedReader] was closed before its payload
	// had been read, so the padding was never drained and nothing about the
	// end of the stream is known. It says what did not happen rather than what
	// is wrong with the stream.
	ErrIncompleteRead = errors.New("envelope: padded reader closed before its payload was read")

	// errBadReadCount: the source returned a count outside 0..len(p).
	errBadReadCount = errors.New("envelope: source returned an invalid read count")

	// errNegativeRemainder: an exactReader was built with a negative count,
	// which PaddedSize screens out ahead of the only construction site. Kept
	// distinct from errBadReadCount so the blame lands on the caller, not on r.
	errNegativeRemainder = errors.New("envelope: negative payload size in the padded sealer")

	// errPaddingInvariant: a post-condition of the sealer did not hold. Nothing
	// a source does can cause it, so it is deliberately not an ErrSource* value
	// that would send the report to the caller instead of to this package.
	errPaddingInvariant = errors.New("envelope: padded sealer post-condition failed")
)

// PaddedSize reports the padded plaintext length used for an n-byte payload:
// the 9-byte frame plus n, rounded up by the Padmé rule (Nikitin et al.,
// "Reducing Metadata Leakage from Encrypted Files", PoPETs 2019). Padmé keeps
// only the top log2(log2(L)) bits of a length significant, which caps overhead
// near 12% and collapses every length in a bucket onto one on-disk size.
//
// The sealed file is streamHeaderSize + PaddedSize(n) + TagSize*chunks bytes,
// with chunks = ceil(PaddedSize(n)/chunkSize). Returns 0 for a negative n, or
// one too large to frame.
func PaddedSize(n int64) int64 {
	if n < 0 || n > math.MaxInt64-paddingFrameSize {
		return 0
	}
	return padme(n + paddingFrameSize)
}

// padme rounds l up so only its top log2(log2(l)) bits are significant, a
// bucket width of 2^(floor(log2 l) - floor(log2 log2 l) - 1).
//
// It is frozen for paddingVersion 0x01. OpenPaddedStreamAAD checks the padding
// it drains against PaddedSize, so changing this rule does not merely reinter-
// pret old files, it makes every one of them unreadable. A new rule needs a new
// paddingVersion and an opener that dispatches on it, not just a new constant.
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

// zeroReader is an endless source of zeros. Padding is keystream-XORed like any
// other plaintext, so zeros are indistinguishable from data once sealed.
type zeroReader struct{}

// Read fills p with zeros and never fails.
func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// exactReader yields exactly left bytes from r, then EOF, failing as soon as r
// proves shorter or longer. Catching the mismatch here is what keeps a wrong
// size cheap: the padding is generated only afterwards, so a caller who
// declares a terabyte and delivers nothing gets an error rather than a whole
// Padmé bucket written to dst.
//
// r is caller-supplied, so Read is defensive. It never re-reads r after EOF (a
// drained reader may answer os.ErrClosed), keeps errors sticky, answers a
// zero-length read without touching r, rejects a count that would drive left
// negative, and gives up with io.ErrNoProgress on a source that only ever
// returns (0, nil). What it cannot promise is on atEnd.
type exactReader struct {
	r     io.Reader
	left  int64 // payload bytes still owed by r
	empty int   // consecutive (0, nil) reads from r, reset by any progress
	eof   bool  // r has reported io.EOF, so it must not be read again
	err   error // sticky: the first failure, or io.EOF, ends the reader
}

// Read fills p from r, never past the declared size.
func (e *exactReader) Read(p []byte) (int, error) {
	// Checked ahead of the zero-length case on purpose: a finished reader
	// answers every call alike. Do not reorder.
	if e.err != nil {
		return 0, e.err
	}
	if len(p) == 0 {
		// Must not reach atEnd, which would consume a byte of r.
		return 0, nil
	}
	if e.left < 0 {
		// Unreachable today; guarded so p[:e.left] can never panic.
		return 0, e.fail(errNegativeRemainder)
	}
	if e.left == 0 {
		return 0, e.fail(e.atEnd())
	}

	if int64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	if n < 0 || n > len(p) {
		return 0, e.fail(errBadReadCount)
	}
	e.left -= int64(n)

	if errors.Is(err, io.EOF) {
		e.eof = true
		if e.left > 0 {
			return n, e.fail(fmt.Errorf("%w: %d bytes missing", ErrSourceShort, e.left))
		}
		// Exactly the declared length. Hold the EOF back so the next call still
		// runs atEnd, which will not re-read r now that eof is set.
		err = nil
	}
	if err != nil {
		return n, e.fail(err)
	}
	if n == 0 {
		// Passed up as the contract says, but not forever: the same bound as
		// atEnd, or the caller's io.ReadFull spins instead of this loop.
		e.empty++
		if e.empty >= maxConsecutiveEmptyReads {
			return 0, e.fail(io.ErrNoProgress)
		}
		return 0, nil
	}
	e.empty = 0
	return n, nil
}

// atEnd reports how the payload ended: io.EOF if r is exhausted, ErrSourceLong
// if it holds more, since stopping quietly would seal a frame that silently
// truncates the source.
//
// Two costs. Finding that extra byte consumes it, and a plain io.Reader has
// nowhere to push it back, so src must not be read on after ErrSourceLong; pass
// io.LimitReader(src, size) to keep a framed payload intact. And the check runs
// only if something drives the reader to its end, which is why
// SealPaddedStreamAAD verifies reachedEnd instead of trusting the read pattern.
func (e *exactReader) atEnd() error {
	if e.eof {
		return io.EOF // already answered; re-reading r is pointless and unsafe
	}

	var probe [1]byte
	for i := maxConsecutiveEmptyReads; i > 0; i-- {
		n, err := e.r.Read(probe[:])
		switch {
		case n > 0:
			return ErrSourceLong
		case errors.Is(err, io.EOF):
			e.eof = true
			return io.EOF
		case err != nil:
			// named, so a drain failure is not mistaken for a payload one
			return fmt.Errorf("envelope: checking for data past the declared size: %w", err)
		}
		// (0, nil) means nothing happened; ask again rather than call it EOF.
	}
	return io.ErrNoProgress
}

// reachedEnd reports whether r was driven far enough to confirm its size, which
// is also the point where trailing data would have been caught.
func (e *exactReader) reachedEnd() bool { return e.eof }

// fail records err as the terminal state and returns it unchanged, so every
// later call answers identically. io.EOF is recorded too, which is what makes
// the end of the payload idempotent.
func (e *exactReader) fail(err error) error {
	if err != nil && e.err == nil {
		e.err = err
	}
	return err
}

// SealPaddedFile seals srcPath into a newly created dstPath, padding the
// payload so the file size no longer reveals the exact plaintext length. It is
// shorthand for [Scheme.SealPaddedFileAAD] with a nil AAD.
func (s *Scheme) SealPaddedFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.SealPaddedFileAAD(masterKey, dstPath, srcPath, nil)
}

// SealPaddedFileAAD seals srcPath into a newly created dstPath with the
// payload padded to [PaddedSize], binding aad into every chunk, and returns
// the number of real payload bytes sealed. Like
// [Scheme.SealFileAAD] it streams chunk by chunk and refuses to overwrite an
// existing destination.
//
// Only the length is hidden, and only to within one Padmé bucket. File names,
// timestamps and access patterns leak independently; see [RandomHex].
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
// newly created dstPath, verifying aad, and returns the number of payload
// bytes recovered. The padding is authenticated but not written out. Failures
// are [ErrNoPaddingFrame] or [ErrPaddingMalformed], both matching [ErrNotPadded].
//
// Prefer this over [Scheme.OpenPaddedStreamAAD] when the destination is a file:
// payload reaches dst before the trailing padding is authenticated, and this
// form removes the partial dst on any error, which the stream form leaves to
// the caller.
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

// SealPaddedStreamAAD reads size bytes from src, pads them out to [PaddedSize]
// and seals the result to dst as one stream, binding aad into every chunk. It
// returns the real payload length, not the padded one.
//
// Use it when the plaintext is not a file: a buffer, an HTTP body, a pipe.
// Padding is generated as the sealer asks for it and only one chunk is
// buffered, so nothing is staged on disk. [Scheme.SealPaddedFileAAD] is this
// with size taken from a Stat.
//
// size must match what src actually delivers, because the padded length is
// fixed before the first chunk is sealed. A short or long source fails at the
// payload boundary with [ErrSourceShort] or [ErrSourceLong] before any padding
// is written, so a wrong size costs a header rather than gigabytes of zeros,
// which is what makes size safe to take from an untrusted peer. dst is then
// left holding a partial stream no reader will accept; discarding it is the
// caller's job (the file wrappers do it for you), and the returned count is the
// padded bytes written so far.
//
// Only [Scheme.OpenPaddedStreamAAD] can read this back, never
// [Scheme.OpenStreamAAD]: the AAD domain-separates the two formats. The bytes
// on disk are unchanged, so a sealed file still does not reveal that it is
// padded.
func (s *Scheme) SealPaddedStreamAAD(masterKey []byte, dst io.Writer, src io.Reader, size int64, aad []byte) (int64, error) {
	target := PaddedSize(size)
	if target == 0 {
		return 0, ErrSourceSize
	}

	var frame [paddingFrameSize]byte
	frame[0] = paddingVersion
	// size >= 0 (PaddedSize rejected anything else), so this is the plain
	// two's-complement round-trip read back below.
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
		// Nothing drove src to its end, so it was never checked for trailing
		// data. io.MultiReader does drive it, but that is io.MultiReader's
		// property rather than exactReader's.
		return n, errPaddingInvariant
	}
	if n != target {
		// Belt and braces: exactReader already enforces the payload length, so
		// reaching here means the frame or padding arithmetic is wrong.
		return n, errPaddingInvariant
	}
	return size, nil
}

// PaddedReader reads the payload out of a stream sealed by
// [Scheme.SealPaddedStreamAAD] and throws the padding away. Reach for it when
// you would rather pull the payload yourself than have
// [Scheme.OpenPaddedStreamAAD] push it into an [io.Writer]: an HTTP handler,
// say, can set Content-Length from [PaddedReader.Size] before writing any body.
//
// Watch the ending. The payload runs out before the stream does, and the
// padding behind it still has to be authenticated, so what you have read is
// not trustworthy until you reach the end. Reading to [io.EOF], or getting a
// nil error from [PaddedReader.WriteTo], takes you there. Reading Size bytes
// and stopping leaves you one call short, and [PaddedReader.Close] is what runs
// the check for you.
//
// Errors are sticky: the first one ends the reader, whether it came from the
// stream or from a writer that stopped accepting bytes. A PaddedReader is not
// safe for concurrent use.
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

// OpenPaddedReaderAAD returns a [PaddedReader] over src, verifying aad. The
// stream header and the padding frame are both read and checked here, so a
// stream that is not a readable padded one is reported before any payload byte
// is handed out, and [PaddedReader.Size] is known from the start.
//
// The frame sits inside the first chunk, so the length it states has been
// authenticated by the time this returns. That is not a promise the rest of the
// stream matches it: a truncated body still fails later with
// [ErrPaddingMalformed].
//
// Like [Scheme.OpenPaddedStreamAAD] this never accepts a plain
// [Scheme.SealStream] blob, since the AAD domain-separates the two formats; one
// fails here with [ErrStreamAuth], indistinguishable from a wrong key. Retry
// with [Scheme.OpenReaderAAD] over a fresh reader to tell those apart.
func (s *Scheme) OpenPaddedReaderAAD(masterKey []byte, src io.Reader, aad []byte) (*PaddedReader, error) {
	r, err := s.openReader(masterKey, src, paddedStreamTag, aad)
	if err != nil {
		return nil, err
	}

	var frame [paddingFrameSize]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNoPaddingFrame
		}
		return nil, err
	}
	if frame[0] != paddingVersion {
		return nil, ErrNoPaddingFrame
	}
	size := binary.BigEndian.Uint64(frame[1:])
	if size > math.MaxInt64 {
		return nil, ErrPaddingMalformed
	}
	n := int64(size) // #nosec G115 -- bounded above

	// How much padding the sealer must have written. Knowing it up front is
	// what lets the drain be bounded rather than open-ended: everything read is
	// authenticated, so a hostile blob is not a forgery risk, but a frame
	// claiming a small payload inside a huge stream should not be able to make
	// the reader chew through all of it before complaining. want is at least
	// size+paddingFrameSize because padme never contracts, so the subtraction
	// cannot go negative.
	want := PaddedSize(n)
	if want == 0 {
		return nil, ErrPaddingMalformed
	}

	return &PaddedReader{r: r, size: n, left: n, pad: want - paddingFrameSize - n}, nil
}

// Size is the payload length taken from the stream's authenticated frame, known
// before any payload byte is read. It is the plaintext length the padding hides
// from anyone looking at the file, so a handler can set Content-Length from it.
//
// The frame is authentic, but the stream behind it can still be truncated, so a
// response sized from Size may yet end early with [ErrPaddingMalformed].
func (r *PaddedReader) Size() int64 { return r.size }

// Read hands out the payload and never the padding. It returns [io.EOF] only
// once exactly the padding [PaddedSize] calls for has been drained and the
// stream has ended there, so a clean EOF means the whole stream authenticated.
func (r *PaddedReader) Read(p []byte) (int, error) {
	// Checked ahead of the zero-length case on purpose, as in exactReader: a
	// finished reader answers every call alike. Do not reorder.
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		// Must not reach finish, which would end the reader on a call that
		// asked for nothing.
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

// WriteTo drains the payload into dst, which is what [io.Copy] picks up, and
// then authenticates the padding. It returns the number of payload bytes
// written, so a nil error means dst holds the whole payload and the stream
// ended cleanly behind it.
//
// Chunks reach dst as they authenticate, so treat dst as provisional until this
// returns nil: a stream truncated inside its padding leaves a complete payload
// there alongside an error.
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
			// A failing dst ends the reader too. The padding behind an
			// unfinished copy cannot be authenticated without reading a payload
			// nobody wants, and reporting what stopped the copy is more use
			// than reporting that it stopped.
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
// means the payload was complete and the padding behind it authenticated. It
// reads at most the padding, never closes the underlying source, and repeats
// its verdict if called again.
//
// A caller that reads to [io.EOF] does not need it. Close is for the caller
// that reads [PaddedReader.Size] bytes and stops, which lands exactly one call
// short of the padding check, and is the pattern Size invites.
//
// Closing with payload still unread returns [ErrIncompleteRead]. Authenticating
// the tail would mean reading through everything skipped, and this package does
// not drain an unbounded amount behind the caller's back; a reader being
// abandoned holds no resources, so it can simply be dropped instead.
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

// finish drains exactly the padding the frame calls for and requires the stream
// to end there. Draining is not optional: the padding fills whole trailing
// chunks, and only reading them authenticates those chunks and the final-chunk
// flag, so stopping at the payload would accept a stream truncated inside its
// padding.
func (r *PaddedReader) finish() error {
	if _, err := io.CopyN(io.Discard, r.r, r.pad); err != nil {
		if errors.Is(err, io.EOF) {
			return ErrPaddingMalformed
		}
		return err
	}
	r.pad = 0

	// The padding ended where PaddedSize says it should, so the stream must end
	// here too. This read is also what authenticates the final-chunk flag when
	// the padding lands on a chunk boundary.
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

// fail records the terminal state, so every later call answers identically.
// io.EOF is recorded too, which is what makes a clean end idempotent. The
// stream underneath is ended at the same time, which wipes the plaintext chunk
// it is still holding. Only the first call counts: the error that ended the
// reader is the one worth reporting.
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
// into dst, verifying aad, and returns the number of payload bytes written. It
// is [Scheme.OpenPaddedReaderAAD] driven to the end: read the frame, copy out
// exactly the payload it declares, then drain exactly the padding [PaddedSize]
// calls for and require the stream to end there.
//
// Padded and plain streams are domain-separated by AAD, so neither reader can
// be fooled into accepting the other's data, and the two still share a
// byte-identical header on disk. The price is that an ordinary
// [Scheme.SealStream] blob fails here as [ErrStreamAuth], indistinguishable
// from a wrong key: to tell those apart, retry with [Scheme.OpenStreamAAD] over
// a fresh reader, which succeeds only for the unpadded case.
//
// Payload reaches dst before the trailing padding chunks are authenticated.
// Nothing forged gets through, since every chunk is authenticated as it is
// read, but a stream truncated inside its padding leaves dst holding a complete
// payload alongside a non-nil error. Treat dst as provisional until this
// returns nil.
//
// Reach for [Scheme.OpenPaddedReaderAAD] instead when the payload length is
// wanted before the body is written, or when the destination pulls rather than
// being pushed to.
func (s *Scheme) OpenPaddedStreamAAD(masterKey []byte, dst io.Writer, src io.Reader, aad []byte) (int64, error) {
	r, err := s.OpenPaddedReaderAAD(masterKey, src, aad)
	if err != nil {
		return 0, err
	}
	return r.WriteTo(dst)
}
