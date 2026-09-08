package envelope

// exactReader and zeroReader feed the padded sealer its plaintext. Neither
// knows about padding, so they live here, not in padding.go. Together they turn
// a caller's reader plus a length into a source that hands over exactly that
// many bytes, or fails saying it was short or long.

import (
	"errors"
	"fmt"
	"io"
)

const (
	// How many "no bytes, no error" replies to retry before giving up. They are
	// legal, but a reader that only ever gives them would spin forever. Same
	// limit and error (io.ErrNoProgress) as bufio.
	maxConsecutiveEmptyReads = 100
)

var (
	// the source returned a read count outside 0..len(p)
	errBadReadCount = errors.New("envelope: source returned an invalid read count")

	// Built with a negative size, which PaddedSize already rejects. Separate
	// from errBadReadCount so the blame lands on us, not the caller's reader.
	errNegativeRemainder = errors.New("envelope: negative payload size in the padded sealer")
)

// zeroReader is an endless source of zeros. Once encrypted they look like any
// other data.
type zeroReader struct{}

// Read fills p with zeros and never fails.
func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// exactReader gives exactly left bytes from r, then EOF, and fails as soon as r
// proves shorter or longer. Failing here is what keeps a wrong size cheap: the
// padding comes afterwards, so a bogus length costs an error, not a bucket of
// padding on dst.
//
// r is the caller's, so Read is defensive: no reads after EOF, sticky errors,
// no touching r for an empty p, no negative left, and io.ErrNoProgress for a
// reader stuck on (0, nil). See atEnd for what it cannot promise.
type exactReader struct {
	r     io.Reader
	left  int64 // bytes r still owes us
	empty int   // consecutive (0, nil) reads, reset by any progress
	eof   bool  // r said io.EOF, so don't read it again
	err   error // sticky: the first failure, or io.EOF, ends the reader
}

// Read fills p from r, never past the declared size.
func (e *exactReader) Read(p []byte) (int, error) {
	// Before the empty-p case, so a finished reader answers every call alike.
	if e.err != nil {
		return 0, e.err
	}
	if len(p) == 0 {
		// don't fall through to atEnd, which eats a byte of r
		return 0, nil
	}
	if e.left < 0 {
		// unreachable; p[:e.left] can't panic
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
		// Exact length. Hold the EOF back so the next call runs atEnd; eof is
		// set now, so it won't re-read r.
		err = nil
	}
	if err != nil {
		return n, e.fail(err)
	}
	if n == 0 {
		// Pass it up, but bounded, or the caller's io.ReadFull spins instead.
		e.empty++
		if e.empty >= maxConsecutiveEmptyReads {
			return 0, e.fail(io.ErrNoProgress)
		}
		return 0, nil
	}
	e.empty = 0
	return n, nil
}

// atEnd reports how the payload ended: io.EOF if r is empty, ErrSourceLong if
// it holds more. Two catches: the probe byte is consumed and can't be pushed
// back (wrap src in io.LimitReader to keep it usable), and this only runs if
// something reads to the end, which is why the sealer checks reachedEnd.
func (e *exactReader) atEnd() error {
	if e.eof {
		// already answered; reading r again is unsafe
		return io.EOF
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
			// wrapped, so this isn't mistaken for a payload failure
			return fmt.Errorf("envelope: checking for data past the declared size: %w", err)
		}
		// (0, nil) means nothing happened; ask again rather than call it EOF.
	}
	return io.ErrNoProgress
}

// reachedEnd reports whether r was read far enough to confirm its size, which
// is also where trailing data would have been caught.
func (e *exactReader) reachedEnd() bool { return e.eof }

// fail records the terminal error and returns it unchanged, so later calls
// answer alike. io.EOF is recorded too, so the end repeats cleanly.
func (e *exactReader) fail(err error) error {
	if err != nil && e.err == nil {
		e.err = err
	}
	return err
}
