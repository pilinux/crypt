// Package main - example usage of AES encryption - decryption
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

	// derive key from the user's secret pass using argon2id
	key128 := argon2.IDKey([]byte(secretPass), salt, uint32(timeCost), uint32(memoryCost), uint8(cpuCost), 128/8)
	key192 := argon2.IDKey([]byte(secretPass), salt, uint32(timeCost), uint32(memoryCost), uint8(cpuCost), 192/8)
	key256 := argon2.IDKey([]byte(secretPass), salt, uint32(timeCost), uint32(memoryCost), uint8(cpuCost), 256/8)

	// encrypt the data with AES-128 in GCM
	ciphertext128, nonce128, err := crypt.EncryptAesGcm(key128, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext (AES-128):", ciphertext128)

	// decrypt the data with AES-128 in GCM
	plaintext, err := crypt.DecryptAesGcm(key128, nonce128, ciphertext128)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data with AES-192 in GCM
	ciphertext192, nonce192, err := crypt.EncryptAesGcm(key192, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext (AES-192):", ciphertext192)

	// decrypt the data with AES-192 in GCM
	plaintext, err = crypt.DecryptAesGcm(key192, nonce192, ciphertext192)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data with AES-256 in GCM
	ciphertext256, nonce256, err := crypt.EncryptAesGcm(key256, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext (AES-256):", ciphertext256)

	// decrypt the data with AES-256 in GCM
	plaintext, err = crypt.DecryptAesGcm(key256, nonce256, ciphertext256)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data with AES-128 in GCM using EncryptAesGcmWithNonceAppended function
	ciphertext128, err = crypt.EncryptAesGcmWithNonceAppended(key128, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext (AES-128):", ciphertext128)

	// decrypt the data with AES-128 in GCM using DecryptAesGcmWithNonceAppended function
	plaintext, err = crypt.DecryptAesGcmWithNonceAppended(key128, ciphertext128)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data with AES-192 in GCM using EncryptAesGcmWithNonceAppended function
	ciphertext192, err = crypt.EncryptAesGcmWithNonceAppended(key192, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext (AES-192):", ciphertext192)

	// decrypt the data with AES-192 in GCM using DecryptAesGcmWithNonceAppended function
	plaintext, err = crypt.DecryptAesGcmWithNonceAppended(key192, ciphertext192)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)

	// encrypt the data with AES-256 in GCM using EncryptAesGcmWithNonceAppended function
	ciphertext256, err = crypt.EncryptAesGcmWithNonceAppended(key256, text)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ciphertext (AES-256):", ciphertext256)

	// decrypt the data with AES-256 in GCM using DecryptAesGcmWithNonceAppended function
	plaintext, err = crypt.DecryptAesGcmWithNonceAppended(key256, ciphertext256)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("plaintext:", plaintext)
}
