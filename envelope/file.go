package envelope

import (
	"io"
	"os"
)

// filePerm is the mode of the files [Scheme.SealFile] and [Scheme.OpenFile]
// create: owner read/write only, since both ends handle sensitive material.
const filePerm os.FileMode = 0o600

// SealFile seals srcPath into a newly created dstPath. It is shorthand for
// [Scheme.SealFileAAD] with a nil AAD.
func (s *Scheme) SealFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.SealFileAAD(masterKey, dstPath, srcPath, nil)
}

// SealFileAAD seals srcPath into a newly created dstPath, binding aad into
// every chunk, and returns the number of plaintext bytes sealed. The file is
// streamed chunk by chunk, so its size is limited by the filesystem rather
// than by memory. A file name makes a natural aad.
//
// dstPath must not exist yet: refusing to overwrite is what keeps a mixed-up
// argument order from destroying the source file.
func (s *Scheme) SealFileAAD(masterKey []byte, dstPath, srcPath string, aad []byte) (int64, error) {
	return pipeFile(dstPath, srcPath, func(dst io.Writer, src io.Reader) (int64, error) {
		return s.SealStreamAAD(masterKey, dst, src, aad)
	})
}

// OpenFile opens the sealed file srcPath into a newly created dstPath. It is
// shorthand for [Scheme.OpenFileAAD] with a nil AAD.
func (s *Scheme) OpenFile(masterKey []byte, dstPath, srcPath string) (int64, error) {
	return s.OpenFileAAD(masterKey, dstPath, srcPath, nil)
}

// OpenFileAAD opens the sealed file srcPath into a newly created dstPath,
// verifying aad against the value used at sealing time, and returns the
// number of plaintext bytes recovered. dstPath must not exist yet.
//
// Chunks are written as they authenticate, so a corrupt or truncated input is
// only detected part-way through; the incomplete output is removed before the
// error is returned.
func (s *Scheme) OpenFileAAD(masterKey []byte, dstPath, srcPath string, aad []byte) (int64, error) {
	return pipeFile(dstPath, srcPath, func(dst io.Writer, src io.Reader) (int64, error) {
		return s.OpenStreamAAD(masterKey, dst, src, aad)
	})
}

// pipeFile streams srcPath through fn into a freshly created dstPath, syncs
// it to disk and removes it again if anything went wrong, so a failed run
// never leaves a half-written file behind.
func pipeFile(dstPath, srcPath string, fn func(dst io.Writer, src io.Reader) (int64, error)) (int64, error) {
	// both paths are chosen by the caller; gosec's file-inclusion warning does not apply.
	src, err := os.Open(srcPath) // #nosec G304
	if err != nil {
		return 0, err
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm) // #nosec G304
	if err != nil {
		return 0, err
	}

	n, err := fn(dst, src)
	if err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dstPath)
		return n, err
	}
	return n, nil
}
