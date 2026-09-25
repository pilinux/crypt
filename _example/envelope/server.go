package main

// A small HTTP server for trying the streaming API by hand: upload a real file
// through a real browser form, watch it get sealed and padded without ever
// touching disk as plaintext.
//
// A multipart upload cannot state its length, but it lands in a file, so POST
// /upload pads it on the request path with SealPaddedAtAAD, which seals chunk 0
// last. POST /upload?plain=1 seals it unpadded instead, and POST
// /objects/{id}/pad reseals it padded afterwards: the flow for a destination
// that cannot seek. PUT /upload/{name} takes a raw body, where Content-Length is
// exact, and pads with SealPaddedStreamAAD.
//
// Because the padded and plain forms are domain-separated by AAD, nothing can
// tell them apart from the blob alone; the store records which is which, as
// real code must.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pilinux/crypt/envelope"
)

// defaultMaxUpload caps a single upload unless -max says otherwise. A real
// endpoint wants a bound like this, since padding is computed from a length and
// an attacker-chosen one should not be unbounded; for manual testing the flag
// exists because the library itself has no ceiling, and proving that on a
// multi-gigabyte file is the point.
const defaultMaxUpload = 1 << 30

// maxNameLen trims the display name. It is never used as a path: objects live
// under a random id, so a hostile filename cannot escape the store.
const maxNameLen = 120

// maxUpload is the active cap, 0 for none. Set from -max before the server
// starts and not written again.
var maxUpload int64 = defaultMaxUpload

// chunkSize is what new objects are sealed with. Set from -chunk before the
// server starts and not written again; readers take it from each header.
var chunkSize = envelope.DefaultChunkSize

// limitBody applies the cap, if there is one.
func limitBody(w http.ResponseWriter, r *http.Request) io.ReadCloser {
	if maxUpload <= 0 {
		return r.Body
	}
	return http.MaxBytesReader(w, r.Body, maxUpload)
}

// object is one stored upload. Sealed and Plain are kept apart so the page can
// show what padding costs.
//
// The store holds these by value and hands out copies, so a handler reading an
// object can never be racing the handler that pads one. Its methods take value
// receivers for the same reason: a copy has to answer every question the
// original does, and html/template calls them on slice elements it cannot
// address.
type object struct {
	ID     string
	Name   string
	Padded bool
	Plain  int64  // payload bytes
	Sealed int64  // bytes on disk
	Digest string // sha256 of the plaintext, for verifying a download
	When   time.Time

	// padding is true while a pad request holds this object, so a second one
	// does not repeat the work. Not rendered; the page shows Padded.
	padding bool
}

// Overhead reports the sealed size as a percentage over the payload.
func (o object) Overhead() string {
	if o.Plain == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(o.Sealed-o.Plain)/float64(o.Plain))
}

// Expect reports what this object would occupy on disk once padded, so the
// column is comparable with the sealed size beside it rather than with the
// padded plaintext length, which is 37 + 16*chunks smaller.
func (o object) Expect() int64 {
	padded := envelope.PaddedSize(o.Plain)
	if padded == 0 {
		return 0
	}
	chunks := (padded + int64(chunkSize) - 1) / int64(chunkSize)
	if chunks == 0 {
		chunks = 1
	}
	return envelope.StreamHeaderSize + padded + envelope.TagSize*chunks
}

// store holds the sealed objects and the key material for one server run.
type store struct {
	scheme    *envelope.Scheme
	masterKey []byte
	dir       string

	// mu guards objs and order. Nothing escapes it: objs holds objects by
	// value and every accessor copies, so there is no pointer a handler could
	// still be reading while another writes through it.
	// It also covers swapping in a padded file, so the file and its Padded
	// flag change together.
	mu    sync.Mutex
	objs  map[string]object
	order []string
}

// aad binds a sealed object to its id, so a blob moved to another id no longer
// authenticates.
func (s *store) aad(id string) []byte { return []byte("object:" + id) }

// path is where an object's ciphertext lives. The id is hex from RandomHex, so
// it cannot contain a separator.
func (s *store) path(id string) string { return filepath.Join(s.dir, id+".enc") }

// add records a freshly sealed object.
func (s *store) add(o object) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[o.ID] = o
	s.order = append([]string{o.ID}, s.order...)
}

// get returns a copy of one object, which is the caller's to read for as long
// as it likes: a later pad updates the store, not the copy.
func (s *store) get(id string) (object, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objs[id]
	return o, ok
}

// list returns copies of the objects, newest first.
func (s *store) list() []object {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]object, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.objs[id])
	}
	return out
}

// beginPad claims an object for padding: it reports the object only if it is
// unpadded and nobody else is already padding it, and marks it in flight.
//
// The check and the claim have to be one critical section. Reading Padded,
// doing the reseal and then setting it is a check-then-act: two requests both
// pass the check, both reseal, both rename over the same path, and the second
// may find the first's padded blob where it expected a plain one and report a
// 500 for an object that is perfectly fine.
func (s *store) beginPad(id string) (o object, claimed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objs[id]
	if !ok || o.Padded || o.padding {
		return o, false
	}
	o.padding = true
	s.objs[id] = o
	return o, true
}

// endPad releases a claim, finished or not; a failed attempt can be retried.
func (s *store) endPad(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objs[id]
	if !ok {
		return
	}
	o.padding = false
	s.objs[id] = o
}

// commitPad replaces the plain file with the padded one and sets Padded, while
// holding the lock, so a download never sees the new file with the old flag.
func (s *store) commitPad(id, tmpPath string, sealed int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(tmpPath, s.path(id)); err != nil {
		return err
	}
	o := s.objs[id]
	o.Padded, o.Sealed = true, sealed
	s.objs[id] = o
	return nil
}

// open returns an object and its open file, both taken under the lock so they
// always match; see commitPad.
func (s *store) open(id string) (object, *os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objs[id]
	if !ok {
		return o, nil, os.ErrNotExist
	}
	f, err := os.Open(s.path(id))
	return o, f, err
}

// serve runs the upload server until interrupted. dir is where ciphertext goes
// (empty for a fresh temp dir), limit caps one upload (0 for none), chunk is
// the chunk size new objects are sealed with, and debug turns on the [debug]
// lines.
func serve(addr, dir string, limit int64, chunk int, debug bool) error {
	if chunk < envelope.MinChunkSize || chunk > envelope.MaxChunkSize {
		return fmt.Errorf("-chunk %d is outside %d..%d", chunk, envelope.MinChunkSize, envelope.MaxChunkSize)
	}
	maxUpload, chunkSize = limit, chunk
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
		ChunkSize:   chunk,
	})

	// Same bootstrap as the demos: derive a KEK, generate a master key, and in
	// real code persist only the wrapped form.
	kek, err := scheme.DeriveKEK("0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		return err
	}
	defer envelope.Zero(kek)
	masterKey, err := envelope.GenerateMasterKey()
	if err != nil {
		return err
	}
	if _, err := envelope.WrapKey(kek, masterKey); err != nil {
		return err
	}

	if dir == "" {
		if dir, err = os.MkdirTemp("", "crypt-envelope-server-"); err != nil {
			return err
		}
	} else if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	s := &store{scheme: scheme, masterKey: masterKey, dir: dir, objs: map[string]object{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /upload", s.upload)
	mux.HandleFunc("PUT /upload/{name}", s.uploadRaw)
	mux.HandleFunc("POST /objects/{id}/pad", s.pad)
	mux.HandleFunc("GET /objects/{id}", s.download)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		// ReadHeaderTimeout bounds the headers, which are small. Nothing bounds
		// the body or the response: Go's WriteTimeout covers the whole handler,
		// so any value at all would cut a large transfer part-way, and a
		// multi-gigabyte upload is exactly what this is for.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	limitText := "none"
	if maxUpload > 0 {
		limitText = fmt.Sprintf("%d bytes", maxUpload)
	}
	fmt.Printf("envelope upload server on http://%s\n", addr)
	fmt.Printf("ciphertext dir: %s\n", dir)
	fmt.Printf("upload cap: %s (-max), chunk size: %d bytes (-chunk)\n", limitText, chunkSize)
	fmt.Println("memory stays at two chunks at most whatever the file size; the pad")
	fmt.Println("button reseals beside the original, so size the disk for 2x")
	fmt.Println("the master key lives only in memory, so the files die with the process")
	if debug {
		fmt.Println("-debug: [debug] lines trace the header, chunk 0 and last chunk of every")
		fmt.Println("padded upload, payload length and first bytes included")
	}
	fmt.Println()
	base := "http://" + addr
	cmds := [][2]string{
		{"curl '" + base + "/'", "list objects and their ids (HTML page)"},
		{"curl -T ./somefile '" + base + "/upload/somefile'", "raw body: padded, length from Content-Length"},
		{"curl -F file=@./somefile '" + base + "/upload'", "multipart: padded, no length needed"},
		{"curl -F file=@./somefile '" + base + "/upload?plain=1'", "multipart: unpadded, pad it later"},
		{"curl -X POST '" + base + "/objects/<id>/pad'", "pad an unpadded object"},
		{"curl -D - -o out.bin '" + base + "/objects/<id>'", "download; headers carry X-Plaintext-Sha256"},
	}
	width := 0
	for _, c := range cmds {
		width = max(width, len(c[0]))
	}
	for _, c := range cmds {
		fmt.Printf("  %-*s  # %s\n", width, c[0], c[1])
	}
	fmt.Println()
	if debug {
		installDebugHook()
	}
	return srv.ListenAndServe()
}

// upload takes a browser multipart form. The part carries no length, but it
// lands in a file, so SealPaddedAtAAD pads it on the request path; ?plain=1
// seals it unpadded instead. Either way it streams, and the plaintext is never
// staged anywhere.
func (s *store) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = limitBody(w, r)
	plain := r.URL.Query().Has("plain")

	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected a multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// The field name is not checked: any part carrying a filename is taken. A
	// part without one is an ordinary text field, which is the easy mistake to
	// make in a REST client, so say so rather than redirect as if it worked.
	sealed := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, "reading form: "+err.Error(), http.StatusBadRequest)
			return
		}
		if part.FileName() == "" {
			_ = part.Close()
			continue
		}
		if err := s.sealPart(part, plain); err != nil {
			http.Error(w, "sealing upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = part.Close()
		sealed++
	}
	if sealed == 0 {
		http.Error(w, "no file part in the form: the field must be sent as a file, not text. "+
			"In Postman that is Body > form-data, then set the key's type dropdown to File. "+
			"The key name itself does not matter.", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sealPart streams one multipart file part into the store, padded, or unpadded
// if plain is set. The caller has already established that the part carries a
// filename, so the concrete type comes in rather than an io.Reader plus a way
// to rediscover it.
func (s *store) sealPart(part *multipart.Part, plain bool) error {
	name := part.FileName()
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}

	id, err := envelope.RandomHex(16)
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(s.path(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	// The digest is taken as the bytes go past, so verifying a later download
	// costs no second pass and no copy of the plaintext.
	sum := sha256.New()
	src := io.TeeReader(part, sum)
	var n int64
	if plain {
		n, err = s.scheme.SealStreamAAD(s.masterKey, dst, src, s.aad(id))
	} else {
		// dst is a fresh *os.File, so chunk 0 can be written last, once the
		// length it carries is known.
		n, err = s.scheme.SealPaddedAtAAD(s.masterKey, dst, src, s.aad(id))
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(s.path(id))
		return err
	}

	info, err := os.Stat(s.path(id))
	if err != nil {
		// nothing references this file, so it would never be cleaned up
		_ = os.Remove(s.path(id))
		return err
	}
	s.add(object{
		ID: id, Name: name, Padded: !plain, Plain: n, Sealed: info.Size(),
		Digest: hex.EncodeToString(sum.Sum(nil)), When: time.Now(),
	})
	logChunks(id, info.Size())
	return nil
}

// uploadRaw takes the file as the whole request body, where Content-Length is
// exact, so it pads with SealPaddedStreamAAD, which checks the body against it.
func (s *store) uploadRaw(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength < 0 {
		http.Error(w, "need a Content-Length; chunked bodies cannot be padded on the request path", http.StatusLengthRequired)
		return
	}
	if maxUpload > 0 && r.ContentLength > maxUpload {
		http.Error(w, fmt.Sprintf("body is %d bytes, over the %d byte cap; raise it with -max", r.ContentLength, maxUpload), http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = limitBody(w, r)

	name := r.PathValue("name")
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	id, err := envelope.RandomHex(16)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dst, err := os.OpenFile(s.path(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sum := sha256.New()
	n, err := s.scheme.SealPaddedStreamAAD(s.masterKey, dst,
		io.TeeReader(r.Body, sum), r.ContentLength, s.aad(id))
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// A declared size the body does not deliver lands here as
		// ErrSourceShort or ErrSourceLong; the partial file is ours to remove.
		_ = os.Remove(s.path(id))
		status := http.StatusInternalServerError
		if errors.Is(err, envelope.ErrSourceSize) {
			status = http.StatusBadRequest
		}
		http.Error(w, "sealing upload: "+err.Error(), status)
		return
	}

	info, err := os.Stat(s.path(id))
	if err != nil {
		_ = os.Remove(s.path(id))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.add(object{
		ID: id, Name: name, Padded: true, Plain: n, Sealed: info.Size(),
		Digest: hex.EncodeToString(sum.Sum(nil)), When: time.Now(),
	})
	logChunks(id, info.Size())
	fmt.Fprintf(w, "sealed %s as %s: %d payload bytes -> %d on disk (padded)\n", name, id, n, info.Size())
}

// pad reseals a stored object with padding: open the plain stream, seal the
// plaintext straight back out padded, then swap it in atomically. The plaintext
// only ever exists one chunk at a time, in memory.
func (s *store) pad(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.get(id); !ok {
		http.NotFound(w, r)
		return
	}

	// One claim per object: whoever gets it does the work, everyone else is
	// redirected to a page that will show the result.
	o, claimed := s.beginPad(id)
	if !claimed {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	defer s.endPad(id)

	src, err := os.Open(s.path(id))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = src.Close() }()

	plain, err := s.scheme.OpenReaderAAD(s.masterKey, src, s.aad(id))
	if err != nil {
		http.Error(w, "opening stored object: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmp, err := os.CreateTemp(s.dir, "pad-*.enc")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = s.scheme.SealPaddedStreamAAD(s.masterKey, tmp, plain, o.Plain, s.aad(id))
	if err == nil {
		// Reach the platter before the rename: this replaces the only copy of
		// the object, so a crash in between must not leave a short file where a
		// whole one was. The library's own pipeFile syncs for the same reason.
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		http.Error(w, "padding: "+err.Error(), http.StatusInternalServerError)
		return
	}
	info, err := os.Stat(tmp.Name())
	if err == nil {
		err = s.commitPad(id, tmp.Name(), info.Size())
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	syncDir(s.dir) // make the rename itself durable

	logChunks(id, info.Size())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// syncDir flushes a directory entry, which is what makes a rename survive a
// crash. Best effort: on a filesystem that refuses to open a directory for
// this there is nothing useful to report or do.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// download streams the plaintext back. Which opener to use comes from the
// store, not from the blob: the two formats are domain-separated, so nothing in
// the file says which it is.
func (s *store) download(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o, src, err := s.open(id)
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = src.Close() }()

	// A padded object states its own length: the frame is authenticated with
	// the first chunk, so the pull form knows Size before any body is written
	// and Content-Length need not come from the store at all. Opening here also
	// means a bad blob is a clean 500 rather than a truncated 200.
	length := o.Plain
	var padded *envelope.PaddedReader
	if o.Padded {
		padded, err = s.scheme.OpenPaddedReaderAAD(s.masterKey, src, s.aad(id))
		if err != nil {
			http.Error(w, "opening stored object: "+err.Error(), http.StatusInternalServerError)
			return
		}
		length = padded.Size()
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(length))
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+template.URLQueryEscaper(o.Name))
	w.Header().Set("X-Plaintext-Sha256", o.Digest)

	// Bytes reach the client before the trailing chunks authenticate, and a
	// response cannot be recalled once sent. A file destination would be
	// removed on error; here the only honest signal is to cut the connection,
	// which a wrong Content-Length already does.
	if padded != nil {
		_, err = padded.WriteTo(w)
	} else {
		_, err = s.scheme.OpenStreamAAD(s.masterKey, w, src, s.aad(id))
	}
	if err != nil {
		log.Printf("download %s failed after %d bytes: %v", id, length, err)
	}
}

// index renders the upload form and the stored objects.
func (s *store) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, s.list()); err != nil {
		log.Printf("render: %v", err)
	}
}

// indexTmpl is html/template, so an uploaded filename is escaped rather than
// reflected into the page.
var indexTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<meta charset="utf-8"><title>envelope upload</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{border-bottom:1px solid #ddd;padding:.4rem .5rem;text-align:left}
 td.n{text-align:right;font-variant-numeric:tabular-nums}
 code{font-size:.85em;color:#555}
 .tag{padding:.1rem .4rem;border-radius:.2rem;font-size:.8em}
 .plain{background:#fde9c8}.padded{background:#cfe9cf}
</style>
<h1>envelope streaming upload</h1>
<p>A multipart upload states no length, but it lands in a file, so it is sealed
<b>padded</b> anyway: chunk 0, which carries the length, is written last. Upload
it <b>plain</b> to pad it afterwards and watch the size snap to a Padm&eacute;
bucket. Nothing is ever written to disk as plaintext.</p>

<form method="post" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file" required>
  <button type="submit">upload padded</button>
  <button type="submit" formaction="/upload?plain=1">upload plain</button>
</form>

<table>
<tr><th>name</th><th>state</th><th class="n">payload</th><th class="n">on disk</th>
    <th class="n">overhead</th><th class="n">padded would be</th><th></th></tr>
{{range .}}
<tr>
  <td>{{.Name}}<br><code>{{.ID}}</code></td>
  <td>{{if .Padded}}<span class="tag padded">padded</span>{{else}}<span class="tag plain">plain</span>{{end}}</td>
  <td class="n">{{.Plain}}</td>
  <td class="n">{{.Sealed}}</td>
  <td class="n">{{.Overhead}}</td>
  <td class="n">{{if .Padded}}-{{else}}{{.Expect}}{{end}}</td>
  <td>
    <a href="/objects/{{.ID}}">download</a>
    {{if not .Padded}}
    <form method="post" action="/objects/{{.ID}}/pad" style="display:inline">
      <button type="submit">pad</button>
    </form>
    {{end}}
  </td>
</tr>
{{else}}
<tr><td colspan="7">nothing uploaded yet</td></tr>
{{end}}
</table>

<p><code>X-Plaintext-Sha256</code> on a download is the digest taken while
sealing, so <code>shasum -a 256</code> on the recovered file should match.</p>
`))
