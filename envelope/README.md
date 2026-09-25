# crypt/envelope

Envelope encryption for data at rest, built on the root `crypt` package.

You keep one secret outside your database. It wraps a random master key, which
you store alongside your data. Every value you seal gets its own key, derived
from the master key and a random salt, and is encrypted with
XChaCha20-Poly1305. Rotating the secret means re-wrapping the master key and
nothing else.

![Diagram: the key ladder, the three ways to seal (single-shot, streaming, padded stream), and the open path that mirrors them](envelope-flow.png)

```text
envelope (0x01): version(1) || saltLen(1) || salt(16) || nonce(24) || ciphertext || tag(16)
stream   (0x81): version(1) || saltLen(1) || salt(16) || chunkSize(4 BE) || noncePrefix(15) || chunk...

secret --HKDF--> KEK --wraps--> master key --HKDF + salt--> sub-key --> XChaCha20-Poly1305
```

## Contents

- [crypt/envelope](#cryptenvelope)
  - [Contents](#contents)
  - [Quick start](#quick-start)
  - [Which function](#which-function)
  - [Keys](#keys)
  - [Wire format](#wire-format)
    - [Wrapped master key (72 bytes)](#wrapped-master-key-72-bytes)
    - [Single-shot envelope (version `0x01`)](#single-shot-envelope-version-0x01)
    - [Streaming format (version `0x81`)](#streaming-format-version-0x81)
    - [Padded stream](#padded-stream)
  - [Errors](#errors)
  - [Rules worth knowing](#rules-worth-knowing)
  - [What the ciphertext reveals](#what-the-ciphertext-reveals)
  - [Source files](#source-files)

## Quick start

```go
scheme := envelope.New(envelope.Config{
	KEKLabel:    "myapp:kek:v1",         // frozen: changing it orphans data
	SubKeyLabel: "myapp:data-subkey:v1", // frozen too
})

// Once: generate the master key and store it wrapped.
kek, err := scheme.DeriveKEK(secret) // secret: >= 32 machine-random bytes
masterKey, err := envelope.GenerateMasterKey()
wrapped, err := envelope.WrapKey(kek, masterKey) // persist this
envelope.Zero(kek)

// Every start: derive the KEK again and unwrap. ErrEnvelopeAuth means the secret changed.
kek, err = scheme.DeriveKEK(secret)
masterKey, err = envelope.UnwrapKey(kek, wrapped)
envelope.Zero(kek)

// Small values. The AAD ties a token to its row, so tokens cannot be swapped.
aad := []byte("user:42:email")
token, err := scheme.SealStringAAD(masterKey, "alice@example.com", aad)
email, err := scheme.OpenStringAAD(masterKey, token, aad)
```

## Which function

| You have | Seal with | Open with |
| --- | --- | --- |
| a string, `[]byte` or `int64` | `SealString`, `SealBytes`, `SealInt64` | `OpenString`, `OpenBytes`, `OpenInt64` |
| a file | `SealFile` | `OpenFile` |
| an `io.Reader` / `io.Writer` | `SealStream`, or `SealWriter` | `OpenStream`, or `OpenReader` |
| a file whose size must stay hidden | `SealPaddedFile` | `OpenPaddedFile` |
| a reader of known size, size hidden | `SealPaddedStream` | `OpenPaddedStream`, or `OpenPaddedReader` |
| a reader of unknown size, into an `io.WriterAt` such as a file | `SealPaddedAt` | `OpenPaddedStream`, or `OpenPaddedReader` |

```go
// Files. The destination must not exist yet; a partial one is removed on error.
n, err := scheme.SealFileAAD(masterKey, "report.pdf.enc", "report.pdf", aad)
n, err = scheme.OpenFileAAD(masterKey, "report.opened.pdf", "report.pdf.enc", aad)

// Writer. Check io.Copy's error; only Close finishes the stream.
w, err := scheme.SealWriterAAD(masterKey, dst, aad)
defer w.Abort() // does nothing after a successful Close
if _, err := io.Copy(w, src); err != nil {
	return err
}
err = w.Close()

// Reader.
r, err := scheme.OpenReaderAAD(masterKey, src, aad)
defer r.Abort() // wipes the decrypted chunk if you stop early
_, err = io.Copy(dst, r)

// Padded reader. The payload size is known before you read the body.
pr, err := scheme.OpenPaddedReaderAAD(masterKey, src, aad)
length := pr.Size() // e.g. for Content-Length
_, err = io.Copy(dst, pr)
err = pr.Close() // checks the padding
```

## Keys

| Key | Size | Produced by | Lives where |
| --- | --- | --- | --- |
| Application secret | >= 32 bytes (`MinSecretLength`) | your own randomness, e.g. `openssl rand -hex 32` | env var / secret manager, never on the wire |
| KEK | 32 (`KeySize`) | `HKDF-SHA256(ikm = secret, salt = nil, info = KEKLabel)` | memory only, `Zero` it after wrapping |
| Master key (DEK) | 32 | `crypto/rand`, generated once ever | stored *wrapped* under the KEK |
| Item sub-key | 32 | `HKDF-SHA256(ikm = masterKey, salt = 16-byte random salt, info = SubKeyLabel)` | one per sealed value, wiped internally |
| Stream sub-key | 32 | the same derivation, run **once per stream**, never per chunk | inside the AEAD for the stream's lifetime |

Never on the wire: the secret, the KEK, the unwrapped master key, sub-keys, labels
and the caller's AAD.

## Wire format

Sizes in bytes, integers big-endian.

### Wrapped master key (72 bytes)

`WrapKey(kek, masterKey)` is a plain
`crypt.EncryptByteXChacha20poly1305WithNonceAppended` call: no envelope header,
no version byte, no AAD. This is the one value you persist alongside your data.

```text
nonce(24) || ciphertext(32) || tag(16)      no header, no AAD
```

| Part | Example |
| --- | --- |
| KEK | `4a70898149320291f112d82f27de499623ec674fa78bcd24faa1f52e7c8c431d` |
| master key | `a81998575dbf4d61208267a180ef3adf0ce5deb5645c16537de66382ff4a56b4` |
| nonce | `292a54a73ab81b36fae84305315e352b02832e5f3e3262e6` |
| ciphertext | `6b967eab91be966c974d7da3215716c3429ce4463d11434b1ca141161bfe21bd` |
| tag | `2670c07f7df390442716129b886f9f74` |
| stored blob (base64) | `KSpUpzq4Gzb66EMFMV41KwKDLl8+MmLma5Z+q5G+lmyXTX2jIVcWw0Kc5EY9EUNLHKFBFhv+Ib0mcMB/ffOQRCcWEpuIb590` |

### Single-shot envelope (version `0x01`)

`SealBytes`, `SealString`, `SealInt64`: the whole value in memory, one sub-key
and one random nonce per value.

```text
┌─────────┬─────────┬──────┬───────┬────────────────┬─────┐
│ version │ saltLen │ salt │ nonce │   ciphertext   │ tag │
│    1    │    1    │  16  │   24  │ len(plaintext) │  16 │
└─────────┴─────────┴──────┴───────┴────────────────┴─────┘
└────── header (18) ───────┘└─ XChaCha20-Poly1305 output ─┘

key = HKDF-SHA256(masterKey, salt, SubKeyLabel)
AD  = header || aad
```

| Offset | Field | Size | Value |
| --- | --- | --- | --- |
| 0 | version | 1 | `0x01` |
| 1 | saltLen | 1 | `0x10`, anything else is `ErrBadEnvelope` |
| 2 | salt | 16 | random per value |
| 18 | nonce | 24 | random per value |
| 42 | ciphertext | n | |
| 42+n | tag | 16 | |

| Size | Formula | Example |
| --- | --- | --- |
| blob | `58 + n` | 17-byte string: 75 |
| base64 token | `4 * ceil((58 + n) / 3)` chars | 100 chars |
| `int64` token | always 66 bytes, 88 chars | the value is 8 bytes big-endian, so the size never leaks it |

Both examples use the master key above and the Quick start labels
(`SubKeyLabel` = `myapp:data-subkey:v1`), so they open with those values.

`SealStringAAD(masterKey, "alice@example.com", []byte("user:42:email"))`, a
17-byte string:

| Field | Size | Value |
| --- | --- | --- |
| version | 1 | `01` |
| saltLen | 1 | `10` (= 16) |
| salt | 16 | `ac2d87c6417da6983652b7ee79ed0870` |
| nonce | 24 | `b7af08ca1ce210951f0267149ddcaebbe4f5625d94141c30` |
| ciphertext | 17 | `c855a85043da64d4d14461d66933714102` |
| tag | 16 | `13fd87417a048d093d2b99251ee4874e` |
| blob | 75 | `0110ac2d87c6417da6983652b7ee79ed0870b7af08ca1ce210951f0267149ddcaebbe4f5625d94141c30c855a85043da64d4d14461d6693371410213fd87417a048d093d2b99251ee4874e` |
| token | 100 chars | `ARCsLYfGQX2mmDZSt+557Qhwt68IyhziEJUfAmcUndyuu+T1Yl2UFBwwyFWoUEPaZNTRRGHWaTNxQQIT/YdBegSNCT0rmSUe5IdO` |

`SealInt64(masterKey, 42)`, no AAD:

| Field | Size | Value |
| --- | --- | --- |
| version | 1 | `01` |
| saltLen | 1 | `10` (= 16) |
| salt | 16 | `4589b01af706ab5ba6dcfe2fe9e352f1` |
| nonce | 24 | `153db20803b79f798ff2e19ad2da262b78b183c825af2687` |
| ciphertext | 8 | `dc71d1cac75dd5e0` (the plaintext is `000000000000002a`) |
| tag | 16 | `9a798d9bcb498de34176af4bab77ac8a` |
| token | 88 chars | `ARBFibAa9warW6bc/i/p41LxFT2yCAO3n3mP8uGa0tomK3ixg8glryaH3HHRysdd1eCaeY2by0mN40F2r0urd6yK` |

Sealing the same value twice gives a new salt and nonce, so equal plaintexts
never produce equal tokens.

### Streaming format (version `0x81`)

`SealStream`, `SealWriter`, `SealFile`: memory stays at one chunk whatever the
input size.

```text
┌─────────┬─────────┬──────┬───────────┬─────────────┐┌─────────┬─────────┬─────┬───────────┐
│ version │ saltLen │ salt │ chunkSize │ noncePrefix ││ chunk 0 │ chunk 1 │ ... │ chunk N-1 │
│    1    │    1    │  16  │     4     │      15     ││  ct+tag │  ct+tag │     │   ct+tag  │
└─────────┴─────────┴──────┴───────────┴─────────────┘└─────────┴─────────┴─────┴───────────┘
└─── header (37), authenticated with every chunk ────┘└──── one Poly1305 tag per chunk ─────┘

header(37) || chunk 0 || chunk 1 || ... || chunk N-1

header = version(1) || saltLen(1) || salt(16) || chunkSize(4) || noncePrefix(15)
chunk  = ciphertext(chunkSize, the last one may be shorter) || tag(16)

key    = HKDF-SHA256(masterKey, salt, SubKeyLabel)      once per stream
nonce  = noncePrefix(15) || counter(8) || final(1)      per chunk: final = 0x01 on the last one
AD     = header || SHA-256(len(tag)(8) || tag || aad)   computed once, identical for every chunk
```

| Offset | Field | Size | Value |
| --- | --- | --- | --- |
| 0 | version | 1 | `0x81` (the high bit keeps it apart from `0x01`) |
| 1 | saltLen | 1 | `0x10` |
| 2 | salt | 16 | random per stream |
| 18 | chunkSize | 4 | `MinChunkSize` (1 KiB) .. `MaxChunkSize` (64 MiB), default 1 MiB |
| 22 | noncePrefix | 15 | random per stream |

The `tag` in the AD is a format tag that is never stored:
`pilinux/crypt/envelope:stream:v1` for plain streams,
`pilinux/crypt/envelope:padded:v1` for padded ones. Neither reader opens the
other's streams.

**Size:** `37 + n + 16 * max(1, ceil(n / chunkSize))`, so a 10 GiB file at the
default chunk size grows by 160 KiB. An exact multiple of the chunk size gets no
empty extra chunk; empty input is one 16-byte chunk.

| n (1 KiB chunks) | Chunks | Sealed |
| --- | --- | --- |
| 0 | 1 | 53 |
| 500 | 1 | 553 |
| 1024 | 1 | 1077 |
| 2048 | 2 | 2117 |
| 2500 | 3 | 2585 |

Example: 2500 random bytes, 1 KiB chunks,
header `811018f2250d998368c02f22874f359c0024000004006e759a18fea1a1621e3d6bbadd7fb0`:

| Field | Size | Value |
| --- | --- | --- |
| version | 1 | `81` |
| saltLen | 1 | `10` (= 16) |
| salt | 16 | `18f2250d998368c02f22874f359c0024` |
| chunkSize | 4 | `00000400` (= 1024) |
| noncePrefix | 15 | `6e759a18fea1a1621e3d6bbadd7fb0` |

| Chunk | Plaintext | Counter, flag | On the wire | Tag |
| --- | --- | --- | --- | --- |
| 0 | 1024 | `0000000000000000` `00` | 1040 | `fda2e5a001286ea1b6376d9c0be018f2` |
| 1 | 1024 | `0000000000000001` `00` | 1040 | `24e06be6ade0c3ec2532c36254bce8d0` |
| 2 | 452 | `0000000000000002` `01` | 468 | `3007794b82748b1ccacc327b52a7253d` |

Total: 37 + 1040 + 1040 + 468 = 2585.

| Tampering | Result |
| --- | --- |
| flip a bit, reorder, duplicate, drop or append chunks | `ErrStreamAuth` |
| truncate | `ErrStreamAuth`: the last chunk read is not flagged final; `ErrBadStream` if the cut falls inside or right after the header, or 1 to 15 bytes into a chunk |
| edit the header | `ErrStreamAuth`, or `ErrBadStream` / `ErrInvalidChunkSize` if it no longer parses |
| wrong key or AAD | `ErrStreamAuth` |
| envelope fed to a stream reader, or the reverse | `ErrBadStream` / `ErrBadEnvelope` |

### Padded stream

A stream hides content, not length: its size gives `n` away. The padded forms
frame and pad the payload inside an ordinary `0x81` stream.

```text
sealed plaintext = version(1)=0x01 || realLen(8) || payload || zeros
padded length    = PaddedSize(n) = padme(9 + n)
on disk          = 37 + PaddedSize(n) + 16 * ceil(PaddedSize(n) / chunkSize)
```

Padmé keeps only the top `log2(log2(L))` bits of `L`, the frame plus the
payload. The overhead on `L` is at most about 12% below 256 bytes, 6% below
64 KiB and 3% below 4 GiB. On average it is about 3% on the Padmé paper's
real-world datasets, and 1 to 2% for sizes spread evenly on a log scale from
1 KB to 1 GB. On a tiny payload the 9-byte frame adds to that: 120 bytes pad to 144, 20%.
Buckets are 2 KiB wide near 96 KB, 16 KiB near 1 MB, 16 MiB near 1 GB. Measured
at 1 MiB chunks:

| Payload | `PaddedSize` | Padded file | Unpadded file |
| --- | --- | --- | --- |
| 94,500 | 96,256 | **96,309** | 94,553 |
| 96,037 | 96,256 | **96,309** | 96,090 |
| 96,200 | 96,256 | **96,309** | 96,253 |
| 100,000 | 100,352 | 100,405 | 100,053 |

| Sealer | Size from | Memory |
| --- | --- | --- |
| `SealPaddedStream(masterKey, dst, src, size)` | the `size` argument | one chunk |
| `SealPaddedFile(masterKey, dstPath, srcPath)` | `Stat` on the open file | one chunk |
| `SealPaddedAt(masterKey, dst, src)` | counted; chunk 0 is sealed last and written at offset 37 | two chunks |

All three write the same format. When `dst` is not an `io.WriterAt` and the
size is unknown, seal plain now and pad later:

```go
_, err := scheme.SealStreamAAD(masterKey, dst, part, aad) // request path

n, ok := envelope.PlaintextLen(sealedSize, chunkSize) // later
r, err := scheme.OpenReaderAAD(masterKey, src, aad)
_, err = scheme.SealPaddedStreamAAD(masterKey, dst2, r, n, aad)
```

## Errors

| Error | Returned when |
| --- | --- |
| `ErrSecretTooShort` | secret under 32 bytes |
| `ErrInvalidKeySize` | a key argument is not 32 bytes, or an unwrapped key is not |
| `ErrInvalidSaltSize` | a salt argument is not 16 bytes |
| `ErrBadEnvelope` | malformed envelope or base64 |
| `ErrEnvelopeAuth` | envelope or wrapped key fails authentication: wrong key, wrong AAD, altered byte |
| `ErrNotAnInteger` | authentic token that is not an 8-byte `int64` |
| `ErrInvalidChunkSize` | chunk size out of range, above `MaxAcceptedChunkSize`, or a `ChunkSize` above it at seal time |
| `ErrBadStream` | bad stream header, or a chunk too short to hold a tag |
| `ErrStreamAuth` | a chunk fails authentication, including a plain stream opened as padded |
| `ErrStreamClosed` | `Write` after `Close` |
| `ErrStreamAborted` | any call after `Abort`, unless the stream had already ended or failed: that verdict stands |
| `ErrNotPadded` | umbrella for the next two |
| `ErrNoPaddingFrame` | authentic padded stream without a frame: a newer padded format |
| `ErrPaddingMalformed` | the stream contradicts its frame: short payload, wrong padding length, non-zero padding |
| `ErrSourceSize` | umbrella for the next three; returned bare for a negative or unrepresentable size |
| `ErrSourceIrregular` | `SealPaddedFile` source is not a regular file |
| `ErrSourceShort` / `ErrSourceLong` | source delivered less or more than the declared size |
| `ErrIncompleteRead` | `PaddedReader.Close` with payload still unread |

Authentication errors never say which of wrong key, wrong AAD or altered bytes
it was.

## Rules worth knowing

- **Some things can never change.** The labels, `padme` and the two format tags
  are baked into every sealed value; changing one makes existing data
  unreadable. `ChunkSize` is fine to change, since each stream records its own.
- **Don't trust output until the call returns nil.** Chunks reach `dst` as
  they are verified. `SealFile`/`OpenFile` and the padded file forms remove a
  partial destination; with a stream, discard `dst` yourself.
- **Only `Close` completes a stream, and only if nothing failed.** A source
  error that the writer reads itself, including `io.ErrUnexpectedEOF` from a
  cut-off body, is sticky, so `Close` returns it and writes no final chunk.
  That covers `SealStream`, `SealFile` and `io.Copy` from a source without a
  `WriteTo` method. A source that has one, a `StreamReader` for instance,
  makes `io.Copy` call it instead, and its failure never reaches the writer:
  check `io.Copy`'s error and let `Abort` discard the stream, or `Close` seals
  what arrived as a valid short stream. `Abort` discards a stream on purpose.
- **Read a `PaddedReader` to `io.EOF`, or call `Close`.** The padding behind
  the payload is only checked there.
- **A wrong `size` never costs padding.** `SealPaddedStream` fails at the
  payload boundary, before any padding is written, so `dst` gets no more than
  `src` actually delivered and `size` may come from a client.
  Detecting extra data consumes one byte of `src`; wrap a framed source in
  `io.LimitReader`.
- **`SealPaddedAt` needs an empty `dst`.** Old bytes past the new end would
  break the stream.
- **Padded and plain streams look identical.** Opening a plain one as padded
  is `ErrStreamAuth`; retry with `OpenStream` over a fresh reader to tell it
  from a wrong key.
- **A reader allocates the chunk size in the header before anything
  authenticates.** Set `Config.MaxAcceptedChunkSize` to the largest chunk you
  write so a stranger cannot cost you 64 MiB per open.
- **`padme` and the format tags are frozen like the labels.** Changing `padme`
  breaks every padded stream; changing a tag breaks every stream of its format.

## What the ciphertext reveals

| Visible | Hidden |
| --- | --- |
| which format, and a stream's chunk size and chunk count | plaintext, keys, secret, labels, AAD |
| exact plaintext length: `blob - 58`, or `sealed - 37 - 16 * chunks` | an `int64`'s magnitude; a padded payload's length within its bucket |
| salt, nonce, nonce prefix (not secret) | whether two blobs hold the same plaintext |
| | which master key sealed it |

Padding hides the length only. Names, timestamps and access patterns still leak;
`RandomHex` makes an opaque file name.

## Source files

| File | Contents |
| --- | --- |
| `envelope.go` | constants, errors, `Config`, `Scheme`, `New`/`Default`, envelope header codec |
| `keys.go` | `DeriveKEK`, `GenerateMasterKey`, `WrapKey`/`UnwrapKey`, `Zero` |
| `cipher.go` | `DeriveSubKey`, `GenerateSalt`, `Seal`/`Open` for bytes, string and `int64` |
| `stream.go` | stream format, `StreamWriter`, `StreamReader`, `SealStream`/`OpenStream`, `PlaintextLen` |
| `file.go` | `SealFile`/`OpenFile` over `pipeFile` (`O_EXCL`, mode `0600`, removed on error) |
| `padding.go` | `PaddedSize`, padded sealers, `PaddedReader`, padded openers |
| `exactreader.go` | `exactReader` (delivers exactly `size` bytes or fails) and `zeroReader` |
| `hash.go` | `Sha256Hex`, `RandomHex` |

Tests: `go test -race -cover ./...`. Stream tests use 1 KiB chunks so
multi-chunk cases stay cheap. The runnable walkthrough is
[`_example/envelope`](../_example/envelope/main.go).
