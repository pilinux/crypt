package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"
)

// testChunkSize keeps the multi-chunk tests cheap: the smallest chunk the
// format allows.
const testChunkSize = MinChunkSize

// streamScheme returns a scheme that streams in small chunks.
func streamScheme() *Scheme {
	return New(Config{ChunkSize: testChunkSize})
}

// randomData returns n random bytes.
func randomData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read error: %v", err)
	}
	return b
}

// sealedSize is the expected ciphertext length for n plaintext bytes.
func sealedSize(n int) int {
	chunks := n/testChunkSize + 1
	if n > 0 && n%testChunkSize == 0 {
		chunks = n / testChunkSize
	}
	return streamHeaderSize + n + chunks*TagSize
}

// streamSizes exercises every boundary case around the chunk size.
var streamSizes = []struct {
	name string
	n    int
}{
	{name: "empty", n: 0},
	{name: "one", n: 1},
	{name: "belowChunk", n: testChunkSize - 1},
	{name: "exactChunk", n: testChunkSize},
	{name: "aboveChunk", n: testChunkSize + 1},
	{name: "twoChunks", n: 2 * testChunkSize},
	{name: "threeChunksAndChange", n: 3*testChunkSize + 7},
}

func TestSealOpenStream(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := randomData(t, tt.n)

			var sealed bytes.Buffer
			n, err := s.SealStream(masterKey, &sealed, bytes.NewReader(plaintext))
			if err != nil {
				t.Fatalf("SealStream error: %v", err)
			}
			if n != int64(tt.n) {
				t.Errorf("sealed %d plaintext bytes, want %d", n, tt.n)
			}
			if sealed.Len() != sealedSize(tt.n) {
				t.Errorf("ciphertext len = %d, want %d", sealed.Len(), sealedSize(tt.n))
			}

			var opened bytes.Buffer
			n, err = s.OpenStream(masterKey, &opened, bytes.NewReader(sealed.Bytes()))
			if err != nil {
				t.Fatalf("OpenStream error: %v", err)
			}
			if n != int64(tt.n) {
				t.Errorf("opened %d plaintext bytes, want %d", n, tt.n)
			}
			if !bytes.Equal(opened.Bytes(), plaintext) {
				t.Error("round-trip mismatch")
			}
		})
	}
}

// TestStreamWriterReader drives the Write/Read path instead of the
// ReadFrom/WriteTo fast path taken by SealStream and OpenStream.
func TestStreamWriterReader(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	for _, tt := range streamSizes {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := randomData(t, tt.n)

			var sealed bytes.Buffer
			w, err := s.SealWriter(masterKey, &sealed)
			if err != nil {
				t.Fatalf("SealWriter error: %v", err)
			}
			// dribble the input in so chunk boundaries fall inside a Write
			for off := 0; off < len(plaintext); off += 7 {
				end := min(off+7, len(plaintext))
				if _, err := w.Write(plaintext[off:end]); err != nil {
					t.Fatalf("Write error: %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close error: %v", err)
			}
			if sealed.Len() != sealedSize(tt.n) {
				t.Errorf("ciphertext len = %d, want %d", sealed.Len(), sealedSize(tt.n))
			}

			r, err := s.OpenReader(masterKey, bytes.NewReader(sealed.Bytes()))
			if err != nil {
				t.Fatalf("OpenReader error: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Error("round-trip mismatch")
			}

			// the stream stays at EOF once it ended
			if _, err := r.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Errorf("read past end: err = %v, want io.EOF", err)
			}
		})
	}
}

func TestStreamHidesPlaintext(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	plaintext := bytes.Repeat([]byte("attack at dawn! "), 200)

	var a, b bytes.Buffer
	if _, err := s.SealStream(masterKey, &a, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("SealStream error: %v", err)
	}
	if _, err := s.SealStream(masterKey, &b, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("SealStream error: %v", err)
	}

	if bytes.Contains(a.Bytes(), []byte("attack at dawn")) {
		t.Error("plaintext appears in the sealed stream")
	}
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two seals of the same input are identical")
	}
}

// seal is a helper returning a sealed stream of n random bytes plus its
// plaintext.
func seal(t *testing.T, s *Scheme, masterKey []byte, n int, aad []byte) (sealed, plaintext []byte) {
	t.Helper()
	plaintext = randomData(t, n)

	var buf bytes.Buffer
	if _, err := s.SealStreamAAD(masterKey, &buf, bytes.NewReader(plaintext), aad); err != nil {
		t.Fatalf("SealStreamAAD error: %v", err)
	}
	return buf.Bytes(), plaintext
}

// openStream is a helper opening a sealed stream into memory.
func openStream(s *Scheme, masterKey, sealed, aad []byte) ([]byte, error) {
	var out bytes.Buffer
	_, err := s.OpenStreamAAD(masterKey, &out, bytes.NewReader(sealed), aad)
	return out.Bytes(), err
}

func TestStreamAAD(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	aad := []byte("user:42:backup.tar")
	sealed, plaintext := seal(t, s, masterKey, 3*testChunkSize, aad)

	t.Run("correctAAD", func(t *testing.T) {
		got, err := openStream(s, masterKey, sealed, aad)
		if err != nil {
			t.Fatalf("OpenStreamAAD error: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Error("round-trip mismatch")
		}
	})

	t.Run("wrongAAD", func(t *testing.T) {
		if _, err := openStream(s, masterKey, sealed, []byte("user:7:backup.tar")); !errors.Is(err, ErrStreamAuth) {
			t.Errorf("err = %v, want ErrStreamAuth", err)
		}
	})

	t.Run("missingAAD", func(t *testing.T) {
		if _, err := openStream(s, masterKey, sealed, nil); !errors.Is(err, ErrStreamAuth) {
			t.Errorf("err = %v, want ErrStreamAuth", err)
		}
	})
}

func TestStreamWrongMasterKey(t *testing.T) {
	s := streamScheme()
	sealed, _ := seal(t, s, newMasterKey(t), 2*testChunkSize, nil)

	if _, err := openStream(s, newMasterKey(t), sealed, nil); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("err = %v, want ErrStreamAuth", err)
	}
}

// TestStreamIntegrity covers every way a stream can be mangled: the chunk
// counter and final flag in the nonce, plus the authenticated header, must
// catch all of them.
func TestStreamIntegrity(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	// four full chunks plus a short final one
	sealed, _ := seal(t, s, masterKey, 4*testChunkSize+11, nil)
	chunk := testChunkSize + TagSize

	tests := []struct {
		name   string
		mangle func(b []byte) []byte
		want   error
	}{
		{
			name:   "flipCiphertextByte",
			mangle: func(b []byte) []byte { b[streamHeaderSize+5] ^= 0xFF; return b },
			want:   ErrStreamAuth,
		},
		{
			name:   "flipFinalTagByte",
			mangle: func(b []byte) []byte { b[len(b)-1] ^= 0xFF; return b },
			want:   ErrStreamAuth,
		},
		{
			name:   "flipSaltByte",
			mangle: func(b []byte) []byte { b[envelopeHeaderSize] ^= 0xFF; return b },
			want:   ErrStreamAuth,
		},
		{
			name:   "flipNoncePrefixByte",
			mangle: func(b []byte) []byte { b[streamHeaderSize-1] ^= 0xFF; return b },
			want:   ErrStreamAuth,
		},
		{
			name:   "flipVersionByte",
			mangle: func(b []byte) []byte { b[0] ^= 0xFF; return b },
			want:   ErrBadStream,
		},
		{
			name:   "shrinkChunkSizeField",
			mangle: func(b []byte) []byte { b[envelopeHeaderSize+SaltSize+3]--; return b },
			want:   ErrStreamAuth,
		},
		{
			name: "zeroChunkSizeField",
			mangle: func(b []byte) []byte {
				clear(b[envelopeHeaderSize+SaltSize : streamHeaderSize-streamNoncePrefixSize])
				return b
			},
			want: ErrInvalidChunkSize,
		},
		{
			name:   "dropFinalChunk",
			mangle: func(b []byte) []byte { return b[:len(b)-(11+TagSize)] },
			want:   ErrStreamAuth,
		},
		{
			name:   "truncateMidChunk",
			mangle: func(b []byte) []byte { return b[:len(b)-7] },
			want:   ErrStreamAuth,
		},
		{
			name: "swapTwoChunks",
			mangle: func(b []byte) []byte {
				first := b[streamHeaderSize : streamHeaderSize+chunk]
				second := b[streamHeaderSize+chunk : streamHeaderSize+2*chunk]
				tmp := append([]byte{}, first...)
				copy(first, second)
				copy(second, tmp)
				return b
			},
			want: ErrStreamAuth,
		},
		{
			name: "duplicateFirstChunk",
			mangle: func(b []byte) []byte {
				copy(b[streamHeaderSize+chunk:streamHeaderSize+2*chunk], b[streamHeaderSize:streamHeaderSize+chunk])
				return b
			},
			want: ErrStreamAuth,
		},
		{
			name: "dropMiddleChunk",
			mangle: func(b []byte) []byte {
				return append(b[:streamHeaderSize+chunk:streamHeaderSize+chunk], b[streamHeaderSize+2*chunk:]...)
			},
			want: ErrStreamAuth,
		},
		{
			name:   "headerOnly",
			mangle: func(b []byte) []byte { return b[:streamHeaderSize] },
			want:   ErrBadStream,
		},
		{
			name:   "truncatedHeader",
			mangle: func(b []byte) []byte { return b[:streamHeaderSize-1] },
			want:   ErrBadStream,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mangled := tt.mangle(append([]byte{}, sealed...))
			if _, err := openStream(s, masterKey, mangled, nil); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestStreamEnvelopeSeparation checks that the two formats reject each other's
// data instead of trying to decrypt it.
func TestStreamEnvelopeSeparation(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	t.Run("envelopeAsStream", func(t *testing.T) {
		blob, err := s.SealBytes(masterKey, bytes.Repeat([]byte("x"), 100))
		if err != nil {
			t.Fatalf("SealBytes error: %v", err)
		}
		if _, err := openStream(s, masterKey, blob, nil); !errors.Is(err, ErrBadStream) {
			t.Errorf("err = %v, want ErrBadStream", err)
		}
	})

	t.Run("streamAsEnvelope", func(t *testing.T) {
		sealed, _ := seal(t, s, masterKey, 100, nil)
		if _, err := s.OpenBytes(masterKey, sealed); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("err = %v, want ErrBadEnvelope", err)
		}
	})
}

func TestStreamChunkSize(t *testing.T) {
	masterKey := newMasterKey(t)

	t.Run("defaultApplied", func(t *testing.T) {
		if got := Default().chunkSize; got != DefaultChunkSize {
			t.Errorf("chunkSize = %d, want %d", got, DefaultChunkSize)
		}
	})

	t.Run("outOfRange", func(t *testing.T) {
		for _, size := range []int{-1, 1, MinChunkSize - 1, MaxChunkSize + 1} {
			s := New(Config{ChunkSize: size})
			if _, err := s.SealWriter(masterKey, io.Discard); !errors.Is(err, ErrInvalidChunkSize) {
				t.Errorf("ChunkSize %d: err = %v, want ErrInvalidChunkSize", size, err)
			}
		}
	})

	t.Run("readFromStreamNotScheme", func(t *testing.T) {
		// a stream carries its own chunk size, so it still opens under a
		// scheme configured with a different one
		sealed, plaintext := seal(t, streamScheme(), masterKey, 3*testChunkSize, nil)

		other := New(Config{ChunkSize: 4 * testChunkSize})
		got, err := openStream(other, masterKey, sealed, nil)
		if err != nil {
			t.Fatalf("OpenStream error: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Error("round-trip mismatch")
		}
	})
}

func TestStreamWriterClosed(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	var sealed bytes.Buffer
	w, err := s.SealWriter(masterKey, &sealed)
	if err != nil {
		t.Fatalf("SealWriter error: %v", err)
	}
	if _, err := w.Write([]byte("done")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	size := sealed.Len()
	if err := w.Close(); err != nil {
		t.Errorf("second Close error: %v", err)
	}
	if sealed.Len() != size {
		t.Error("second Close wrote another chunk")
	}
	if _, err := w.Write([]byte("more")); !errors.Is(err, ErrStreamClosed) {
		t.Errorf("Write after Close: err = %v, want ErrStreamClosed", err)
	}
	if _, err := w.ReadFrom(bytes.NewReader([]byte("more"))); !errors.Is(err, ErrStreamClosed) {
		t.Errorf("ReadFrom after Close: err = %v, want ErrStreamClosed", err)
	}
}

// failWriter fails every write after the first limit bytes.
type failWriter struct {
	limit int
	n     int
}

var errWriteFailed = errors.New("write failed")

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n+len(p) > f.limit {
		return 0, errWriteFailed
	}
	f.n += len(p)
	return len(p), nil
}

func TestStreamWriterStickyError(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	// room for the header only, so the first chunk write fails
	w, err := s.SealWriter(masterKey, &failWriter{limit: streamHeaderSize})
	if err != nil {
		t.Fatalf("SealWriter error: %v", err)
	}
	if _, err := w.Write(randomData(t, 2*testChunkSize)); !errors.Is(err, errWriteFailed) {
		t.Fatalf("Write: err = %v, want errWriteFailed", err)
	}
	// a broken stream must never be finalized into something openable
	if err := w.Close(); !errors.Is(err, errWriteFailed) {
		t.Errorf("Close: err = %v, want errWriteFailed", err)
	}

	// the header write itself fails too
	if _, err := s.SealWriter(masterKey, &failWriter{}); !errors.Is(err, errWriteFailed) {
		t.Errorf("SealWriter: err = %v, want errWriteFailed", err)
	}
}

// errReader fails after handing out n bytes.
type errReader struct {
	n int
}

var errReadFailed = errors.New("read failed")

func (e *errReader) Read(p []byte) (int, error) {
	if e.n == 0 {
		return 0, errReadFailed
	}
	n := min(len(p), e.n)
	e.n -= n
	return n, nil
}

func TestSealStreamSourceError(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	var sealed bytes.Buffer
	_, err := s.SealStream(masterKey, &sealed, &errReader{n: 3 * testChunkSize})
	if !errors.Is(err, errReadFailed) {
		t.Fatalf("SealStream: err = %v, want errReadFailed", err)
	}
	// the aborted stream lacks its final chunk, so it must not open
	if _, err := openStream(s, masterKey, sealed.Bytes(), nil); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("aborted stream opened: err = %v, want ErrStreamAuth", err)
	}
}

func TestStreamHeaderCodec(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, SaltSize)
	prefix := bytes.Repeat([]byte{0xCD}, streamNoncePrefixSize)

	t.Run("roundTrip", func(t *testing.T) {
		header, err := buildStreamHeader(salt, DefaultChunkSize, prefix)
		if err != nil {
			t.Fatalf("buildStreamHeader error: %v", err)
		}
		if len(header) != streamHeaderSize {
			t.Fatalf("header len = %d, want %d", len(header), streamHeaderSize)
		}
		if header[0] != streamVersion || header[0] == envelopeVersion {
			t.Errorf("version = 0x%02x, want 0x%02x", header[0], streamVersion)
		}

		gotSalt, gotSize, gotPrefix, err := parseStreamHeader(header)
		if err != nil {
			t.Fatalf("parseStreamHeader error: %v", err)
		}
		if !bytes.Equal(gotSalt, salt) || gotSize != DefaultChunkSize || !bytes.Equal(gotPrefix, prefix) {
			t.Error("header round-trip mismatch")
		}
	})

	t.Run("buildRejects", func(t *testing.T) {
		if _, err := buildStreamHeader(salt[:4], DefaultChunkSize, prefix); !errors.Is(err, ErrInvalidSaltSize) {
			t.Errorf("short salt: err = %v, want ErrInvalidSaltSize", err)
		}
		if _, err := buildStreamHeader(salt, MaxChunkSize+1, prefix); !errors.Is(err, ErrInvalidChunkSize) {
			t.Errorf("big chunk: err = %v, want ErrInvalidChunkSize", err)
		}
		// a bad prefix length is this package's own bug, not bad input, so it
		// reports the invariant rather than ErrBadStream
		if _, err := buildStreamHeader(salt, DefaultChunkSize, prefix[:4]); !errors.Is(err, errStreamInvariant) {
			t.Errorf("short prefix: err = %v, want errStreamInvariant", err)
		}
		if _, err := buildStreamHeader(salt, DefaultChunkSize, prefix[:4]); errors.Is(err, ErrBadStream) {
			t.Error("short prefix must not report ErrBadStream, which names untrusted input")
		}
	})

	t.Run("parseRejects", func(t *testing.T) {
		header, _ := buildStreamHeader(salt, DefaultChunkSize, prefix)
		if _, _, _, err := parseStreamHeader(header[:streamHeaderSize-1]); !errors.Is(err, ErrBadStream) {
			t.Errorf("short header: err = %v, want ErrBadStream", err)
		}

		badSaltLen := append([]byte{}, header...)
		badSaltLen[1] = SaltSize + 1
		if _, _, _, err := parseStreamHeader(badSaltLen); !errors.Is(err, ErrBadStream) {
			t.Errorf("bad saltLen: err = %v, want ErrBadStream", err)
		}
	})
}

func TestStreamNonce(t *testing.T) {
	prefix := bytes.Repeat([]byte{0x11}, streamNoncePrefixSize)
	var a, b [NonceSize]byte

	streamNonce(a[:], prefix, 7, false)
	if !bytes.Equal(a[:streamNoncePrefixSize], prefix) {
		t.Error("nonce does not start with the prefix")
	}
	if a[NonceSize-1] != 0 {
		t.Error("non-final nonce has the final flag set")
	}

	// the counter and the flag must both change the nonce
	streamNonce(b[:], prefix, 8, false)
	if bytes.Equal(a[:], b[:]) {
		t.Error("counter does not change the nonce")
	}
	streamNonce(b[:], prefix, 7, true)
	if bytes.Equal(a[:], b[:]) || b[NonceSize-1] != 1 {
		t.Error("final flag does not change the nonce")
	}
}

func TestStreamInvalidMasterKey(t *testing.T) {
	s := streamScheme()
	short := []byte("too short")

	if _, err := s.SealWriter(short, io.Discard); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("SealWriter: err = %v, want ErrInvalidKeySize", err)
	}

	sealed, _ := seal(t, s, newMasterKey(t), 10, nil)
	if _, err := s.OpenReader(short, bytes.NewReader(sealed)); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("OpenReader: err = %v, want ErrInvalidKeySize", err)
	}
}

// TestStreamReaderStickyError checks that a reader stays failed: a caller
// looping on Read must never get plaintext after an authentication failure.
func TestStreamReaderStickyError(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	sealed, _ := seal(t, s, masterKey, 2*testChunkSize, nil)
	sealed[len(sealed)-1] ^= 0xFF

	r, err := s.OpenReader(masterKey, bytes.NewReader(sealed))
	if err != nil {
		t.Fatalf("OpenReader error: %v", err)
	}

	// the first chunk authenticates, the tampered final one does not
	if _, err := io.ReadAll(r); !errors.Is(err, ErrStreamAuth) {
		t.Fatalf("ReadAll: err = %v, want ErrStreamAuth", err)
	}
	if _, err := r.Read(make([]byte, 16)); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("Read after failure: err = %v, want ErrStreamAuth", err)
	}
	if _, err := r.WriteTo(io.Discard); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("WriteTo after failure: err = %v, want ErrStreamAuth", err)
	}
}

func TestOpenStreamDestinationError(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	sealed, _ := seal(t, s, masterKey, 2*testChunkSize, nil)

	// room for one chunk of plaintext only
	dst := &failWriter{limit: testChunkSize}
	n, err := s.OpenStream(masterKey, dst, bytes.NewReader(sealed))
	if !errors.Is(err, errWriteFailed) {
		t.Errorf("err = %v, want errWriteFailed", err)
	}
	if n != int64(testChunkSize) {
		t.Errorf("wrote %d bytes before failing, want %d", n, testChunkSize)
	}
}

func TestOpenReaderSourceError(t *testing.T) {
	s := streamScheme()

	// a source that fails before the header is complete reports its own error
	if _, err := s.OpenReader(newMasterKey(t), &errReader{}); !errors.Is(err, errReadFailed) {
		t.Errorf("err = %v, want errReadFailed", err)
	}
}

// countingReader hands out n bytes without allocating, so an allocation count
// taken around it measures the stream alone.
type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	c.n -= int64(len(p))
	return len(p), nil
}

// TestStreamAllocationsPerChunk pins down the property that makes the API
// usable on a 100 GB file: the buffers are allocated once per stream and
// reused, so sealing or opening more chunks costs no extra allocations.
func TestStreamAllocationsPerChunk(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	allocs := func(chunks int) (seal, open float64) {
		size := int64(chunks * testChunkSize)
		seal = testing.AllocsPerRun(10, func() {
			if _, err := s.SealStream(masterKey, io.Discard, &countingReader{n: size}); err != nil {
				t.Fatalf("SealStream error: %v", err)
			}
		})

		var sealed bytes.Buffer
		if _, err := s.SealStream(masterKey, &sealed, &countingReader{n: size}); err != nil {
			t.Fatalf("SealStream error: %v", err)
		}
		blob := sealed.Bytes()
		open = testing.AllocsPerRun(10, func() {
			if _, err := s.OpenStream(masterKey, io.Discard, bytes.NewReader(blob)); err != nil {
				t.Fatalf("OpenStream error: %v", err)
			}
		})
		return seal, open
	}

	// a 100x longer stream must not cost 100x the allocations; a slack of two
	// absorbs measurement noise but still catches a per-chunk allocation
	const slack = 2
	oneSeal, oneOpen := allocs(1)
	manySeal, manyOpen := allocs(100)

	if manySeal > oneSeal+slack {
		t.Errorf("seal allocations grow with the stream: %.0f for 1 chunk, %.0f for 100", oneSeal, manySeal)
	}
	if manyOpen > oneOpen+slack {
		t.Errorf("open allocations grow with the stream: %.0f for 1 chunk, %.0f for 100", oneOpen, manyOpen)
	}
}

// TestStreamAuthDataIsUnambiguous pins the properties that keep the two stream
// formats apart: the binding is fixed width whatever the AAD, it depends on
// the tag, and no tag/AAD pair can borrow bytes across its own boundary. The
// cross-format consequence is in TestPaddedTagCannotBeForgedThroughAAD.
func TestStreamAuthDataIsUnambiguous(t *testing.T) {
	header := bytes.Repeat([]byte{0xAA}, streamHeaderSize)

	t.Run("fixedWidth", func(t *testing.T) {
		for _, aad := range [][]byte{nil, {}, []byte("id"), bytes.Repeat([]byte("x"), 4096)} {
			got := streamAuthData(header, plainStreamTag, aad)
			if len(got) != streamHeaderSize+32 {
				t.Errorf("len = %d for a %d-byte aad, want %d", len(got), len(aad), streamHeaderSize+32)
			}
			if !bytes.Equal(got[:streamHeaderSize], header) {
				t.Error("the header is not carried through verbatim")
			}
		}
	})

	t.Run("nilAndEmptyAgree", func(t *testing.T) {
		if !bytes.Equal(streamAuthData(header, plainStreamTag, nil), streamAuthData(header, plainStreamTag, []byte{})) {
			t.Error("nil and empty aad differ")
		}
	})

	t.Run("tagChangesTheBinding", func(t *testing.T) {
		if bytes.Equal(streamAuthData(header, plainStreamTag, nil), streamAuthData(header, paddedStreamTag, nil)) {
			t.Error("the two format tags produce the same binding")
		}
		if plainStreamTag == paddedStreamTag {
			t.Error("the format tags must stay distinct")
		}
	})

	// The tag length is hashed in first, so a longer tag cannot be made to
	// look like a shorter one whose aad starts with the difference.
	t.Run("noBytesTradeAcrossTheBoundary", func(t *testing.T) {
		a := streamAuthData(header, "ab", []byte("cd"))
		b := streamAuthData(header, "abc", []byte("d"))
		if bytes.Equal(a, b) {
			t.Error("(tag, aad) pairs that concatenate alike produce the same binding")
		}
	})
}

// failingReader delivers n bytes and then fails, the shape of a network source
// that dies part-way through an upload.
type failingReader struct {
	left int
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, f.err
	}
	if len(p) > f.left {
		p = p[:f.left]
	}
	for i := range p {
		p[i] = 'S'
	}
	f.left -= len(p)
	return len(p), nil
}

// TestStreamWriterCloseRefusesAfterSourceFailure is the regression test for the
// footgun `defer w.Close()` used to be. ReadFrom leaving its error unsticky
// meant a failed io.Copy followed by the reflexive deferred Close produced a
// perfectly valid stream holding a prefix of the file, indistinguishable from a
// complete one. The error is sticky now, so Close reports it and writes no
// final chunk.
func TestStreamWriterCloseRefusesAfterSourceFailure(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	errSource := errors.New("network died")

	var sealed bytes.Buffer
	w, err := s.SealWriter(masterKey, &sealed)
	if err != nil {
		t.Fatalf("SealWriter error: %v", err)
	}

	src := &failingReader{left: 2 * testChunkSize, err: errSource}
	if _, err := io.Copy(w, src); !errors.Is(err, errSource) {
		t.Fatalf("io.Copy: err = %v, want the source error", err)
	}

	// the idiomatic deferred Close, which used to finalize the fragment
	if err := w.Close(); !errors.Is(err, errSource) {
		t.Errorf("Close: err = %v, want the sticky source error", err)
	}
	// and again, since Close repeats its verdict
	if err := w.Close(); !errors.Is(err, errSource) {
		t.Errorf("second Close: err = %v, want the same error", err)
	}

	// what reached dst must not open as a complete stream
	if _, err := s.OpenStream(masterKey, io.Discard, bytes.NewReader(sealed.Bytes())); !errors.Is(err, ErrStreamAuth) {
		t.Errorf("the abandoned fragment opened: err = %v, want ErrStreamAuth", err)
	}

	// and the writer is spent
	if _, err := w.Write([]byte("more")); !errors.Is(err, errSource) {
		t.Errorf("Write after failure: err = %v, want the sticky error", err)
	}
}

// TestStreamWriterAbort covers the case no sticky error can catch: nothing went
// wrong with the stream, the caller simply decided not to keep it.
func TestStreamWriterAbort(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)

	t.Run("discardsAGoodStream", func(t *testing.T) {
		var sealed bytes.Buffer
		w, err := s.SealWriter(masterKey, &sealed)
		if err != nil {
			t.Fatalf("SealWriter error: %v", err)
		}
		if _, err := w.Write(randomData(t, 3*testChunkSize)); err != nil {
			t.Fatalf("Write error: %v", err)
		}

		w.Abort()

		if err := w.Close(); !errors.Is(err, ErrStreamAborted) {
			t.Errorf("Close after Abort: err = %v, want ErrStreamAborted", err)
		}
		if _, err := w.Write([]byte("x")); !errors.Is(err, ErrStreamAborted) {
			t.Errorf("Write after Abort: err = %v, want ErrStreamAborted", err)
		}
		if _, err := s.OpenStream(masterKey, io.Discard, bytes.NewReader(sealed.Bytes())); !errors.Is(err, ErrStreamAuth) {
			t.Errorf("an aborted stream opened: err = %v, want ErrStreamAuth", err)
		}
	})

	// the documented `defer w.Abort()` shape: it must not undo a good Close
	t.Run("noOpAfterACleanClose", func(t *testing.T) {
		payload := randomData(t, testChunkSize+7)
		var sealed bytes.Buffer
		w, err := s.SealWriter(masterKey, &sealed)
		if err != nil {
			t.Fatalf("SealWriter error: %v", err)
		}
		defer w.Abort()

		if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
			t.Fatalf("io.Copy error: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close error: %v", err)
		}

		w.Abort() // what the defer will do again

		if err := w.Close(); err != nil {
			t.Errorf("Close after a no-op Abort: err = %v, want nil", err)
		}
		var out bytes.Buffer
		if _, err := s.OpenStream(masterKey, &out, bytes.NewReader(sealed.Bytes())); err != nil {
			t.Fatalf("OpenStream error: %v", err)
		}
		if !bytes.Equal(out.Bytes(), payload) {
			t.Error("payload did not survive a stream that was closed then aborted")
		}
	})

	// an earlier failure is the more useful verdict, so Abort must not mask it
	t.Run("keepsAnEarlierError", func(t *testing.T) {
		// the header write succeeds, the first chunk does not
		w, err := s.SealWriter(masterKey, &failWriterAfter{ok: 1})
		if err != nil {
			t.Fatalf("SealWriter error: %v", err)
		}
		if _, err := w.Write(randomData(t, 2*testChunkSize)); !errors.Is(err, errWriteFailed) {
			t.Fatalf("Write: err = %v, want the destination error", err)
		}
		w.Abort()
		if err := w.Close(); !errors.Is(err, errWriteFailed) {
			t.Errorf("Close: err = %v, want the destination error, not ErrStreamAborted", err)
		}
	})
}

// failWriterAfter accepts ok writes and fails from then on.
type failWriterAfter struct{ ok int }

func (f *failWriterAfter) Write(p []byte) (int, error) {
	if f.ok > 0 {
		f.ok--
		return len(p), nil
	}
	return 0, errWriteFailed
}

// TestStreamReaderWriteToRejectsBadWriters is the regression test for the
// missing io.Copy guards. A destination reporting more than it was given used
// to panic on the reslice, and one reporting (0, nil) forever used to spin.
func TestStreamReaderWriteToRejectsBadWriters(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	sealed, _ := seal(t, s, masterKey, 2*testChunkSize, nil)

	tests := []struct {
		name string
		dst  io.Writer
		want error
	}{
		{name: "overCounting", dst: badWriter{n: func(l int) int { return l + 1 }}, want: errBadWriteCount},
		{name: "negativeCount", dst: badWriter{n: func(int) int { return -1 }}, want: errBadWriteCount},
		{name: "shortWithNoError", dst: badWriter{n: func(l int) int { return l / 2 }}, want: io.ErrShortWrite},
		{name: "neverProgresses", dst: badWriter{n: func(int) int { return 0 }}, want: io.ErrShortWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := s.OpenReader(masterKey, bytes.NewReader(sealed))
			if err != nil {
				t.Fatalf("OpenReader error: %v", err)
			}

			// a panic or a hang here is the bug; the test binary's own timeout
			// catches the hang, and the guards make both an ordinary error
			done := make(chan error, 1)
			go func() { _, e := r.WriteTo(tt.dst); done <- e }()

			select {
			case err := <-done:
				if !errors.Is(err, tt.want) {
					t.Errorf("WriteTo: err = %v, want %v", err, tt.want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("WriteTo did not return: it is spinning on a writer that never progresses")
			}

			// the failure is terminal, so no plaintext leaks out afterwards
			if _, err := io.ReadAll(struct{ io.Reader }{r}); !errors.Is(err, tt.want) {
				t.Errorf("Read after the bad write: err = %v, want the sticky %v", err, tt.want)
			}
		})
	}
}

// badWriter reports whatever n says, which is how a writer breaks the
// io.Writer contract without returning an error.
type badWriter struct{ n func(size int) int }

func (b badWriter) Write(p []byte) (int, error) { return b.n(len(p)), nil }

// afterHeaderWriter passes the stream header through untouched and misreports
// every write after it, so the chunk path is reached with a StreamWriter in
// hand rather than failing at SealWriter.
type afterHeaderWriter struct {
	n    func(size int) int
	seen bool
}

func (a *afterHeaderWriter) Write(p []byte) (int, error) {
	if !a.seen {
		a.seen = true
		return len(p), nil
	}
	return a.n(len(p)), nil
}

// TestSealWriterRejectsBadDestinations is the write-side twin of
// TestStreamReaderWriteToRejectsBadWriters. The reader half checked the count
// its destination reported and the writer half did not, so a destination that
// quietly dropped bytes produced an incomplete stream that Close called a
// success: the one verdict a caller acts on by discarding the plaintext.
func TestSealWriterRejectsBadDestinations(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	plaintext := bytes.Repeat([]byte("A"), 4*testChunkSize)

	tests := []struct {
		name string
		n    func(size int) int
		want error
	}{
		{name: "overCounting", n: func(l int) int { return l + 1 }, want: errBadWriteCount},
		{name: "negativeCount", n: func(int) int { return -1 }, want: errBadWriteCount},
		{name: "shortWithNoError", n: func(l int) int { return l / 2 }, want: io.ErrShortWrite},
		{name: "writesNothing", n: func(int) int { return 0 }, want: io.ErrShortWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/header", func(t *testing.T) {
			// the header is the first write, so a destination this broken is
			// caught before a StreamWriter is handed out at all
			if _, err := s.SealWriter(masterKey, badWriter{n: tt.n}); !errors.Is(err, tt.want) {
				t.Errorf("SealWriter over a bad destination: err = %v, want %v", err, tt.want)
			}
		})

		t.Run(tt.name+"/chunk", func(t *testing.T) {
			dst := &afterHeaderWriter{n: tt.n}
			w, err := s.SealWriter(masterKey, dst)
			if err != nil {
				t.Fatalf("SealWriter error: %v", err)
			}

			_, err = io.Copy(w, bytes.NewReader(plaintext))
			if !errors.Is(err, tt.want) {
				t.Errorf("io.Copy: err = %v, want %v", err, tt.want)
			}
			// the verdict is the point: Close must not call an incomplete
			// stream complete, since a nil here licenses dropping the source
			if err := w.Close(); !errors.Is(err, tt.want) {
				t.Errorf("Close after a lossy destination: err = %v, want the sticky %v", err, tt.want)
			}
		})
	}
}

// TestWriteToDestinationErrorIsSticky pins that a failing destination ends the
// reader rather than leaving it usable. It used to return the error without
// recording it, so a caller could keep reading plaintext out of a stream whose
// delivery had already failed, and the chunk still in the buffer was never
// wiped.
func TestWriteToDestinationErrorIsSticky(t *testing.T) {
	s := streamScheme()
	masterKey := newMasterKey(t)
	sealed, _ := seal(t, s, masterKey, 3*testChunkSize, nil)

	r, err := s.OpenReader(masterKey, bytes.NewReader(sealed))
	if err != nil {
		t.Fatalf("OpenReader error: %v", err)
	}
	if _, err := r.WriteTo(&failWriterAfter{ok: 0}); !errors.Is(err, errWriteFailed) {
		t.Fatalf("WriteTo: err = %v, want the destination error", err)
	}

	if _, err := r.Read(make([]byte, 32)); !errors.Is(err, errWriteFailed) {
		t.Errorf("Read after a failed destination: err = %v, want the sticky error", err)
	}
	if _, err := r.WriteTo(io.Discard); !errors.Is(err, errWriteFailed) {
		t.Errorf("WriteTo again: err = %v, want the sticky error", err)
	}
	for _, b := range r.buf {
		if b != 0 {
			t.Fatal("the plaintext chunk was left in the buffer")
		}
	}
}

// TestMaxAcceptedChunkSize pins the reader ceiling. The header is read before
// anything authenticates and the reader allocates what it names, so a Scheme
// must be able to refuse a chunk size larger than it ever writes.
func TestMaxAcceptedChunkSize(t *testing.T) {
	masterKey := newMasterKey(t)
	wide := New(Config{ChunkSize: 4 * MinChunkSize})
	sealed, payload := seal(t, wide, masterKey, 5*MinChunkSize, nil)

	t.Run("refusesAWiderStream", func(t *testing.T) {
		strict := New(Config{MaxAcceptedChunkSize: MinChunkSize})
		if _, err := strict.OpenStream(masterKey, io.Discard, bytes.NewReader(sealed)); !errors.Is(err, ErrInvalidChunkSize) {
			t.Errorf("err = %v, want ErrInvalidChunkSize", err)
		}
		// and refuses it before allocating for it, i.e. from the header alone
		if _, err := strict.OpenReader(masterKey, bytes.NewReader(sealed[:StreamHeaderSize])); !errors.Is(err, ErrInvalidChunkSize) {
			t.Errorf("header only: err = %v, want ErrInvalidChunkSize", err)
		}
	})

	t.Run("acceptsAtTheCeiling", func(t *testing.T) {
		exact := New(Config{MaxAcceptedChunkSize: 4 * MinChunkSize})
		var out bytes.Buffer
		if _, err := exact.OpenStream(masterKey, &out, bytes.NewReader(sealed)); err != nil {
			t.Fatalf("OpenStream error: %v", err)
		}
		if !bytes.Equal(out.Bytes(), payload) {
			t.Error("payload did not round-trip at the ceiling")
		}
	})

	t.Run("defaultsToMaxChunkSize", func(t *testing.T) {
		if New(Config{}).maxChunkSize != MaxChunkSize {
			t.Error("an unset ceiling must default to MaxChunkSize")
		}
		var out bytes.Buffer
		if _, err := Default().OpenStream(masterKey, &out, bytes.NewReader(sealed)); err != nil {
			t.Errorf("the default ceiling refused an ordinary stream: %v", err)
		}
	})

	t.Run("outOfRangeIsReportedAtStreamCreation", func(t *testing.T) {
		for _, n := range []int{MinChunkSize - 1, MaxChunkSize + 1, -1} {
			bad := New(Config{MaxAcceptedChunkSize: n})
			if _, err := bad.OpenReader(masterKey, bytes.NewReader(sealed)); !errors.Is(err, ErrInvalidChunkSize) {
				t.Errorf("ceiling %d on open: err = %v, want ErrInvalidChunkSize", n, err)
			}
			if _, err := bad.SealWriter(masterKey, io.Discard); !errors.Is(err, ErrInvalidChunkSize) {
				t.Errorf("ceiling %d on seal: err = %v, want ErrInvalidChunkSize", n, err)
			}
		}
	})
}

// TestPlaintextLenInvertsSealedSize pins the exported inversion the example
// used to carry by hand, along with the header size it needed to do the
// arithmetic at all.
func TestPlaintextLenInvertsSealedSize(t *testing.T) {
	if StreamHeaderSize != 2+SaltSize+4+(NonceSize-9) {
		t.Fatalf("StreamHeaderSize = %d, does not match the field layout", StreamHeaderSize)
	}

	t.Run("everySizeRoundTrips", func(t *testing.T) {
		for _, cs := range []int{MinChunkSize, 4096, DefaultChunkSize} {
			for _, n := range []int64{0, 1, int64(cs) - 1, int64(cs), int64(cs) + 1, 3*int64(cs) + 7} {
				chunks := n/int64(cs) + 1
				if n > 0 && n%int64(cs) == 0 {
					chunks = n / int64(cs)
				}
				sealed := StreamHeaderSize + n + TagSize*chunks
				got, ok := PlaintextLen(sealed, cs)
				if !ok || got != n {
					t.Errorf("chunk %d, n %d: got (%d, %v)", cs, n, got, ok)
				}
			}
		}
	})

	// what the example actually does: seal, then recover the length from the
	// sealed size with nothing else recorded
	t.Run("matchesARealStream", func(t *testing.T) {
		s := streamScheme()
		masterKey := newMasterKey(t)
		for _, n := range []int{0, 1, testChunkSize, 3*testChunkSize + 7} {
			sealed, _ := seal(t, s, masterKey, n, nil)
			got, ok := PlaintextLen(int64(len(sealed)), testChunkSize)
			if !ok || got != int64(n) {
				t.Errorf("n %d: got (%d, %v) from %d sealed bytes", n, got, ok, len(sealed))
			}
		}
	})

	t.Run("rejectsWhatCannotBeAStream", func(t *testing.T) {
		for _, sealed := range []int64{0, 1, StreamHeaderSize, StreamHeaderSize + TagSize - 1, -100} {
			if _, ok := PlaintextLen(sealed, MinChunkSize); ok {
				t.Errorf("sealed %d was accepted", sealed)
			}
		}
		if _, ok := PlaintextLen(1<<20, MinChunkSize-1); ok {
			t.Error("an out-of-range chunk size was accepted")
		}
		if _, ok := PlaintextLen(1<<20, MaxChunkSize+1); ok {
			t.Error("an out-of-range chunk size was accepted")
		}
	})
}
