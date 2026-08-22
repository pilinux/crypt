package envelope

// Call flow in this file. The plain forms are nil-AAD shorthands for the AAD
// ones, and SealFile/OpenFile (file.go) reach the stream through pipeFile.
//
//	seal
//	  SealStream[AAD]      drives writer -> ReadFrom -> Close
//	   -> SealWriterAAD     once per stream: GenerateSalt + randomBytes (salt,
//	                        nonce prefix), buildStreamHeader, streamAEAD
//	                        (DeriveSubKey -> XChaCha20), authData, header to dst
//	   -> ReadFrom          fills buf; a one-byte look-ahead decides whether a
//	                        full buffer is a non-final chunk
//	   -> Close             seals the remainder as the final chunk; on error
//	                        abort runs instead, so no final chunk is written
//	  Write / ReadFrom / Close
//	   -> seal              streamNonce -> aead.Seal(buf[:0]) -> dst.Write
//
//	open
//	  OpenStream[AAD]      drives reader -> WriteTo
//	   -> OpenReaderAAD     once per stream: reads and checks the header via
//	                        parseStreamHeader, streamAEAD (same sub-key),
//	                        authData
//	   -> WriteTo           drains the stream a whole chunk at a time
//	  Read / WriteTo
//	   -> readChunk         streamNonce -> aead.Open(buf[:0]); fail wipes buf
//	                        and makes the error sticky

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Chunk sizes for the streaming format. The chunk size is the amount of
// plaintext sealed at a time; each chunk costs one extra Poly1305 tag.
const (
	// DefaultChunkSize is used when a [Config] leaves ChunkSize unset.
	DefaultChunkSize = 1 << 20 // 1 MiB

	// MinChunkSize keeps the per-chunk tag overhead below 2%.
	MinChunkSize = 1 << 10 // 1 KiB

	// MaxChunkSize caps the buffer a reader allocates for a chunk size read
	// from an untrusted stream header.
	MaxChunkSize = 64 << 20 // 64 MiB
)

const (
	// streamVersion tags the streaming format. Its high bit is set so it does
	// not collide with envelopeVersion: neither reader accepts the other's
	// data, and the mismatch is reported instead of failing later as a
	// decryption error.
	streamVersion byte = 0x81

	// streamNoncePrefixSize is the random per-stream part of a chunk nonce.
	// The remaining 9 bytes are the chunk counter and the final-chunk flag.
	streamNoncePrefixSize = NonceSize - streamCounterSize - 1

	// streamCounterSize is the width of the big-endian chunk counter that
	// occupies the middle of every chunk nonce.
	streamCounterSize = 8

	// streamChunkSizeWidth is the byte width of the header field that carries
	// the chunk size.
	streamChunkSizeWidth = 4

	// streamHeaderSize is the fixed header length:
	// version(1) || saltLen(1) || salt || chunkSize(4) || noncePrefix.
	streamHeaderSize = envelopeHeaderSize + SaltSize + streamChunkSizeWidth + streamNoncePrefixSize
)

// Errors returned by the streaming API. Like the rest of the package they are
// deliberately generic and never say which chunk failed or why.
var (
	// ErrInvalidChunkSize is returned when a chunk size, either from a
	// [Config] or read from a stream header, is outside
	// [MinChunkSize]..[MaxChunkSize].
	ErrInvalidChunkSize = errors.New("envelope: chunk size out of range")

	// ErrBadStream is returned when a stream is not well-formed: a bad header
	// or a chunk too short to carry an authentication tag.
	ErrBadStream = errors.New("envelope: malformed ciphertext stream")

	// ErrStreamAuth is returned when a chunk fails authentication: a wrong
	// master key or AAD, modified data, or chunks that were reordered,
	// duplicated, dropped or truncated.
	ErrStreamAuth = errors.New("envelope: stream authentication failed")

	// ErrStreamClosed is returned by [StreamWriter.Write] after the stream has
	// been closed.
	ErrStreamClosed = errors.New("envelope: stream writer is closed")
)

// buildStreamHeader assembles the cleartext stream header. It is authenticated
// with every chunk, so none of its bytes can be altered unnoticed.
func buildStreamHeader(salt []byte, chunkSize int, noncePrefix []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, ErrInvalidSaltSize
	}
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return nil, ErrInvalidChunkSize
	}
	if len(noncePrefix) != streamNoncePrefixSize {
		return nil, ErrBadStream
	}

	header := make([]byte, streamHeaderSize)
	header[0] = streamVersion
	header[1] = byte(SaltSize)

	n := envelopeHeaderSize
	n += copy(header[n:], salt)
	// the range check above bounds chunkSize by MaxChunkSize, so it always
	// fits in the 32-bit field.
	binary.BigEndian.PutUint32(header[n:], uint32(chunkSize)) // #nosec G115
	n += streamChunkSizeWidth
	copy(header[n:], noncePrefix)
	return header, nil
}

// parseStreamHeader validates a stream header and returns the parts needed to
// reconstruct the stream key and nonces (both aliasing header).
func parseStreamHeader(header []byte) (salt []byte, chunkSize int, noncePrefix []byte, err error) {
	if len(header) != streamHeaderSize {
		return nil, 0, nil, ErrBadStream
	}
	if header[0] != streamVersion || int(header[1]) != SaltSize {
		return nil, 0, nil, ErrBadStream
	}

	n := envelopeHeaderSize
	salt = header[n : n+SaltSize]
	n += SaltSize
	size := binary.BigEndian.Uint32(header[n : n+streamChunkSizeWidth])
	if size < MinChunkSize || size > MaxChunkSize {
		return nil, 0, nil, ErrInvalidChunkSize
	}
	n += streamChunkSizeWidth

	// bounded by MaxChunkSize above, so the conversion cannot overflow int.
	return salt, int(size), header[n:], nil // #nosec G115
}

// streamNonce fills dst with the nonce of one chunk:
// noncePrefix || counter (big-endian) || final flag. The counter pins a chunk
// to its position in the stream and the flag marks the last one, so a chunk
// that is moved, repeated, removed or cut off no longer authenticates.
func streamNonce(dst, noncePrefix []byte, counter uint64, final bool) {
	n := copy(dst, noncePrefix)
	binary.BigEndian.PutUint64(dst[n:], counter)
	dst[NonceSize-1] = 0
	if final {
		dst[NonceSize-1] = 1
	}
}

// streamAEAD derives the per-stream sub-key from the master key and salt and
// turns it into a reusable AEAD. The sub-key copy is wiped immediately; the
// AEAD keeps its own, unreachable copy for the lifetime of the stream.
func (s *Scheme) streamAEAD(masterKey, salt []byte) (cipher.AEAD, error) {
	subKey, err := s.DeriveSubKey(masterKey, salt)
	if err != nil {
		return nil, err
	}
	defer Zero(subKey)

	return chacha20poly1305.NewX(subKey)
}

// StreamWriter seals everything written to it as a chained sequence of
// XChaCha20-Poly1305 chunks. Nothing but the header is written until a full
// chunk is buffered, so memory use stays at one chunk regardless of input
// size: the buffer is allocated once and reused, and each chunk is sealed in
// place, so no allocation happens per chunk. A StreamWriter is not safe for
// concurrent use.
type StreamWriter struct {
	dst     io.Writer       // where the ciphertext goes
	aead    cipher.AEAD     // per-stream sub-key, derived from master key + salt
	aad     []byte          // header || caller AAD, authenticated with every chunk
	prefix  []byte          // random per-stream part of the nonce
	nonce   [NonceSize]byte // per-chunk nonce: prefix || counter || final flag
	buf     []byte          // plaintext buffer, len == chunk size, cap == +TagSize
	n       int             // bytes buffered
	next    [1]byte         // ReadFrom look-ahead; a field, so it is not allocated per chunk
	counter uint64          // big-endian chunk counter in the nonce
	closed  bool            // true after Close, so a second call is a no-op
	err     error           // sticky: a failed chunk stops the stream for good
}

// SealWriter returns a [StreamWriter] that seals to dst under a fresh per-
// stream sub-key. It is shorthand for [Scheme.SealWriterAAD] with a nil AAD.
func (s *Scheme) SealWriter(masterKey []byte, dst io.Writer) (*StreamWriter, error) {
	return s.SealWriterAAD(masterKey, dst, nil)
}

// SealWriterAAD is [Scheme.SealWriter] with context binding: aad is
// authenticated with every chunk but neither encrypted nor stored, and
// [Scheme.OpenReaderAAD] must be given the identical value.
//
// The stream header is written to dst immediately; the ciphertext is only
// complete once [StreamWriter.Close] has returned without error. Close
// finalizes whatever has been written so far, so call it only after the whole
// input went in successfully, otherwise the result is a valid stream of
// truncated data.
func (s *Scheme) SealWriterAAD(masterKey []byte, dst io.Writer, aad []byte) (*StreamWriter, error) {
	chunkSize := s.chunkSize
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return nil, ErrInvalidChunkSize
	}

	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}
	prefix, err := randomBytes(streamNoncePrefixSize)
	if err != nil {
		return nil, err
	}
	header, err := buildStreamHeader(salt, chunkSize, prefix)
	if err != nil {
		return nil, err
	}

	aead, err := s.streamAEAD(masterKey, salt)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(header); err != nil {
		return nil, err
	}

	return &StreamWriter{
		dst:    dst,
		aead:   aead,
		aad:    authData(header, aad),
		prefix: prefix,
		buf:    make([]byte, chunkSize, chunkSize+TagSize),
	}, nil
}

// Write buffers p and seals a chunk whenever the buffer is full and more data
// follows. The trailing chunk is held back for [StreamWriter.Close], which is
// what marks it as final.
func (w *StreamWriter) Write(p []byte) (int, error) {
	if err := w.state(); err != nil {
		return 0, err
	}

	written := 0
	for len(p) > 0 {
		if w.n == len(w.buf) {
			if err := w.seal(false); err != nil {
				return written, err
			}
		}
		c := copy(w.buf[w.n:], p)
		w.n += c
		p = p[c:]
		written += c
	}
	return written, nil
}

// ReadFrom drains r into the stream without the intermediate copy Write
// needs, which is what [io.Copy] picks up. It stops at the end of r; the
// buffered remainder becomes the final chunk on [StreamWriter.Close].
func (w *StreamWriter) ReadFrom(r io.Reader) (int64, error) {
	if err := w.state(); err != nil {
		return 0, err
	}

	var total int64
	for {
		// fill the buffer; a short read means r is exhausted. If the buffer
		// was already full this reads nothing and falls through to the peek.
		n, err := io.ReadFull(r, w.buf[w.n:])
		w.n += n
		total += int64(n)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return total, nil
			}
			return total, err
		}

		// the buffer is full, but a full buffer is only a non-final chunk if
		// something follows it, so seal it only after reading the next byte.
		switch m, err := io.ReadFull(r, w.next[:]); {
		case m == 1:
		case errors.Is(err, io.EOF):
			return total, nil
		default:
			return total, err
		}
		total++

		if err := w.seal(false); err != nil {
			return total, err
		}
		w.buf[0] = w.next[0]
		w.n = 1
	}
}

// Close seals the buffered remainder as the final chunk. It does not close
// the underlying writer. Calling it more than once is a no-op.
func (w *StreamWriter) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}

	err := w.seal(true)
	w.closed = true
	Zero(w.buf)
	return err
}

// state reports whether the stream can still accept data.
func (w *StreamWriter) state() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrStreamClosed
	}
	return nil
}

// seal encrypts the buffered plaintext in place and writes it out. A failure
// is sticky, so a half-written stream can never be finalized afterwards.
func (w *StreamWriter) seal(final bool) error {
	streamNonce(w.nonce[:], w.prefix, w.counter, final)

	chunk := w.aead.Seal(w.buf[:0], w.nonce[:], w.buf[:w.n], w.aad)
	if _, err := w.dst.Write(chunk); err != nil {
		w.err = err
		return err
	}

	w.counter++
	w.n = 0
	return nil
}

// abort wipes the buffer and blocks the stream without writing a final chunk,
// so an interrupted stream can never be mistaken for a complete one.
func (w *StreamWriter) abort() {
	w.closed = true
	Zero(w.buf)
}

// StreamReader decrypts a stream produced by a [StreamWriter], one chunk at a
// time, and returns [io.EOF] only after the chunk marked final has been
// authenticated. Like [StreamWriter] it holds a single chunk, allocated once
// and decrypted in place. A StreamReader is not safe for concurrent use.
type StreamReader struct {
	src      io.Reader       // where the ciphertext comes from
	aead     cipher.AEAD     // per-stream sub-key, derived from master key + salt
	aad      []byte          // header || caller AAD, authenticated with every chunk
	prefix   []byte          // random per-stream part of the nonce
	nonce    [NonceSize]byte // per-chunk nonce: prefix || counter || final flag
	buf      []byte          // one ciphertext chunk, decrypted in place
	plain    []byte          // decrypted bytes not yet handed out, aliases buf
	carry    [1]byte         // Read look-ahead; a field, so it is not allocated per chunk
	hasCarry bool            // true if carry is valid, so a full chunk can be final
	counter  uint64          // big-endian chunk counter in the nonce
	final    bool            // true if the last chunk was marked final, so the stream ended cleanly
	err      error           // sticky, io.EOF once the stream ended cleanly
}

// OpenReader returns a [StreamReader] over src. It is shorthand for
// [Scheme.OpenReaderAAD] with a nil AAD.
func (s *Scheme) OpenReader(masterKey []byte, src io.Reader) (*StreamReader, error) {
	return s.OpenReaderAAD(masterKey, src, nil)
}

// OpenReaderAAD returns a [StreamReader] over src, verifying aad against the
// value given at sealing time. It reads and validates the stream header up
// front, including the chunk size, which is taken from the stream and not
// from the [Scheme]: changing Config.ChunkSize never orphans sealed data.
func (s *Scheme) OpenReaderAAD(masterKey []byte, src io.Reader, aad []byte) (*StreamReader, error) {
	header := make([]byte, streamHeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		// too short to be a stream; anything else is the caller's I/O error
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrBadStream
		}
		return nil, err
	}

	salt, chunkSize, prefix, err := parseStreamHeader(header)
	if err != nil {
		return nil, err
	}

	aead, err := s.streamAEAD(masterKey, salt)
	if err != nil {
		return nil, err
	}

	return &StreamReader{
		src:    src,
		aead:   aead,
		aad:    authData(header, aad),
		prefix: prefix,
		buf:    make([]byte, chunkSize+TagSize),
	}, nil
}

// Read fills p from the current chunk, decrypting the next one when it runs
// out. A stream that ends without an authentic final chunk fails with
// [ErrStreamAuth] rather than reporting a clean [io.EOF].
func (r *StreamReader) Read(p []byte) (int, error) {
	for {
		if len(r.plain) > 0 {
			n := copy(p, r.plain)
			r.plain = r.plain[n:]
			return n, nil
		}
		if r.err != nil {
			return 0, r.err
		}
		if r.final {
			r.fail(io.EOF)
			return 0, r.err
		}
		if err := r.readChunk(); err != nil {
			r.fail(err)
			return 0, r.err
		}
	}
}

// WriteTo drains the stream into dst a whole chunk at a time, which is what
// [io.Copy] picks up.
func (r *StreamReader) WriteTo(dst io.Writer) (int64, error) {
	var total int64
	for {
		if len(r.plain) == 0 {
			if r.err != nil {
				if errors.Is(r.err, io.EOF) {
					return total, nil
				}
				return total, r.err
			}
			if r.final {
				r.fail(io.EOF)
				return total, nil
			}
			if err := r.readChunk(); err != nil {
				r.fail(err)
				return total, r.err
			}
			continue
		}

		n, err := dst.Write(r.plain)
		r.plain = r.plain[n:]
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
}

// readChunk reads the next ciphertext chunk and decrypts it in place. A chunk
// is final if it is short or if nothing follows it, which is why a full chunk
// costs a one-byte look-ahead.
func (r *StreamReader) readChunk() error {
	n := 0
	if r.hasCarry {
		r.buf[0] = r.carry[0]
		r.hasCarry = false
		n = 1
	}

	m, err := io.ReadFull(r.src, r.buf[n:])
	n += m
	switch {
	case err == nil:
		switch k, e := io.ReadFull(r.src, r.carry[:]); {
		case k == 1:
			r.hasCarry = true
		case errors.Is(e, io.EOF):
			r.final = true
		default:
			return e
		}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		r.final = true
	default:
		return err
	}

	if n < TagSize {
		return ErrBadStream
	}

	streamNonce(r.nonce[:], r.prefix, r.counter, r.final)
	plain, err := r.aead.Open(r.buf[:0], r.nonce[:], r.buf[:n], r.aad)
	if err != nil {
		return ErrStreamAuth
	}

	r.counter++
	r.plain = plain
	return nil
}

// fail records the terminal state (io.EOF for a clean end) and wipes the
// plaintext left in the buffer.
func (r *StreamReader) fail(err error) {
	r.err = err
	r.plain = nil
	Zero(r.buf)
}

// SealStream seals everything readable from src to dst. It is shorthand for
// [Scheme.SealStreamAAD] with a nil AAD.
func (s *Scheme) SealStream(masterKey []byte, dst io.Writer, src io.Reader) (int64, error) {
	return s.SealStreamAAD(masterKey, dst, src, nil)
}

// SealStreamAAD seals everything readable from src to dst, binding aad into
// every chunk, and returns the number of plaintext bytes sealed. On error the
// stream is abandoned without a final chunk, so a partial dst can never be
// opened as a complete one.
func (s *Scheme) SealStreamAAD(masterKey []byte, dst io.Writer, src io.Reader, aad []byte) (int64, error) {
	w, err := s.SealWriterAAD(masterKey, dst, aad)
	if err != nil {
		return 0, err
	}

	n, err := w.ReadFrom(src)
	if err != nil {
		w.abort()
		return n, err
	}
	return n, w.Close()
}

// OpenStream opens a stream from src into dst. It is shorthand for
// [Scheme.OpenStreamAAD] with a nil AAD.
func (s *Scheme) OpenStream(masterKey []byte, dst io.Writer, src io.Reader) (int64, error) {
	return s.OpenStreamAAD(masterKey, dst, src, nil)
}

// OpenStreamAAD opens a stream from src into dst, verifying aad, and returns
// the number of plaintext bytes written. Chunks are written out as they
// authenticate, so a stream that fails part-way has already produced output:
// treat dst as unusable unless the call returns without error.
func (s *Scheme) OpenStreamAAD(masterKey []byte, dst io.Writer, src io.Reader, aad []byte) (int64, error) {
	r, err := s.OpenReaderAAD(masterKey, src, aad)
	if err != nil {
		return 0, err
	}
	return r.WriteTo(dst)
}
