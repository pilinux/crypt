// Package main - example usage of chacha20poly1305 encryption - decryption
package main

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/pilinux/crypt"
)

func main() {
	text := "Hello world"
	secretPass := ",D'(bHOpO#beU(Fn@~_6Enn3a2n=aEQWg''vz"

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
	ciphertext, nonce, err := crypt.EncryptChacha20poly1305(key, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext:", ciphertext)

	// decrypt the data
	plaintext, err := crypt.DecryptChacha20poly1305(key, nonce, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data using EncryptChacha20poly1305WithNonceAppended function
	ciphertext, err = crypt.EncryptChacha20poly1305WithNonceAppended(key, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext:", ciphertext)

	// decrypt the data using DecryptChacha20poly1305WithNonceAppended function
	plaintext, err = crypt.DecryptChacha20poly1305WithNonceAppended(key, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)
}
