// Package main - example usage of XChaCha20-Poly1305 encryption - decryption
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"

	"github.com/pilinux/crypt"
)

func main() {
	text := "Hello world"
	secretPass := "0123456789abcdef0123456789abcdef01234567"

	// generate a random 256-bit salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		fmt.Println("error generating salt:", err)
		return
	}

	// parameters for argon2 key derivation
	timeCost := 2           // number of iterations
	memoryCost := 64 * 1024 // memory usage in KiB
	cpuCost := 2            // number of threads used
	keyLength := 32         // length of the derived key in bytes

	// derive a 256-bit key from the user's secret pass using argon2id
	key := argon2.IDKey([]byte(secretPass), salt, uint32(timeCost), uint32(memoryCost), uint8(cpuCost), uint32(keyLength))

	// encrypt the data
	ciphertext, nonce, err := crypt.EncryptXChacha20poly1305(key, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext:", ciphertext)

	// decrypt the data
	plaintext, err := crypt.DecryptXChacha20poly1305(key, nonce, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data using EncryptXChacha20poly1305WithNonceAppended function
	ciphertext, err = crypt.EncryptXChacha20poly1305WithNonceAppended(key, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext:", ciphertext)

	// decrypt the data using DecryptXChacha20poly1305WithNonceAppended function
	plaintext, err = crypt.DecryptXChacha20poly1305WithNonceAppended(key, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// ============================================================================
	// encrypt a file (dummy.pdf) using XChaCha20-Poly1305
	// the encrypted file will be saved as dummy.pdf.enc (salt || nonce || ciphertext)
	// ============================================================================
	filename := "dummy.pdf"
	encryptedFilename := filename + ".enc"
	decryptedFilename := "decrypted-" + filename

	// read the file
	pdfBytes, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}

	// encrypt the data
	ciphertext, err = crypt.EncryptByteXChacha20poly1305WithNonceAppended(key, pdfBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	// save the encrypted data to a file, salt first: the salt isn't secret, and
	// without it the key can never be derived again
	err = os.WriteFile(encryptedFilename, append(salt, ciphertext...), 0600)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("encrypted file:", encryptedFilename)

	// ============================================================================
	// decrypt the encrypted file (dummy.pdf.enc) using XChaCha20-Poly1305
	// the decrypted file will be saved as decrypted-dummy.pdf; the original is
	// never touched
	// ============================================================================
	// read the encrypted file
	encryptedPdfBytes, err := os.ReadFile(encryptedFilename)
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(encryptedPdfBytes) < len(salt) {
		fmt.Println("encrypted file is too short")
		return
	}

	// derive the key again from the stored salt, as a later run would have to
	storedSalt, sealed := encryptedPdfBytes[:len(salt)], encryptedPdfBytes[len(salt):]
	key = argon2.IDKey([]byte(secretPass), storedSalt, uint32(timeCost), uint32(memoryCost), uint8(cpuCost), uint32(keyLength))

	// decrypt the data
	decryptedPdfBytes, err := crypt.DecryptByteXChacha20poly1305WithNonceAppended(key, sealed)
	if err != nil {
		fmt.Println(err)
		return
	}

	// save the decrypted data to a file
	err = os.WriteFile(decryptedFilename, decryptedPdfBytes, 0600)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("decrypted file:", decryptedFilename)
}
