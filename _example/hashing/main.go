// Package main - example implementation of different hashing algorithms
package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

/*
SHA256                      // import crypto/sha256
SHA384                      // import crypto/sha512
SHA512                      // import crypto/sha512
SHA3_256                    // import golang.org/x/crypto/sha3
SHA3_384                    // import golang.org/x/crypto/sha3
SHA3_512                    // import golang.org/x/crypto/sha3
SHA512_256                  // import crypto/sha512
BLAKE2b_256                 // import golang.org/x/crypto/blake2b
BLAKE2b_384                 // import golang.org/x/crypto/blake2b
BLAKE2b_512                 // import golang.org/x/crypto/blake2b
*/

func main() {
	data := []byte("hello world")
	optionalKey := []byte("secret")

	// calculate SHA2-256 hash
	sha256Hash := sha256.Sum256(data)
	fmt.Println("sha256Hash:")
	fmt.Println(sha256Hash)
	fmt.Printf("hex: %x\n", sha256Hash)
	fmt.Println("length", len(sha256Hash))
	fmt.Println("")

	// calculate SHA2-384 hash
	sha384Hash := sha512.Sum384(data)
	fmt.Println("sha384Hash:")
	fmt.Println(sha384Hash)
	fmt.Printf("hex: %x\n", sha384Hash)
	fmt.Println("length", len(sha384Hash))
	fmt.Println("")

	// calculate SHA2-512 hash
	sha512Hash := sha512.Sum512(data)
	fmt.Println("sha512Hash:")
	fmt.Println(sha512Hash)
	fmt.Printf("hex: %x\n", sha512Hash)
	fmt.Println("length", len(sha512Hash))
	fmt.Println("")

	// calculate SHA3-256 hash
	sha3_256Hash := sha3.Sum256(data)
	fmt.Println("sha3_256Hash:")
	fmt.Println(sha3_256Hash)
	fmt.Printf("hex: %x\n", sha3_256Hash)
	fmt.Println("length", len(sha3_256Hash))
	fmt.Println("")

	// calculate SHA3-384 hash
	sha3_384Hash := sha3.Sum384(data)
	fmt.Println("sha3_384Hash:")
	fmt.Println(sha3_384Hash)
	fmt.Printf("hex: %x\n", sha3_384Hash)
	fmt.Println("length", len(sha3_384Hash))
	fmt.Println("")

	// calculate SHA3-512 hash
	sha3_512Hash := sha3.Sum512(data)
	fmt.Println("sha3_512Hash:")
	fmt.Println(sha3_512Hash)
	fmt.Printf("hex: %x\n", sha3_512Hash)
	fmt.Println("length", len(sha3_512Hash))
	fmt.Println("")

	// calculate SHA2-512/256 hash
	sha512_256Hash := sha512.Sum512_256(data)
	fmt.Println("sha512_256Hash:")
	fmt.Println(sha512_256Hash)
	fmt.Printf("hex: %x\n", sha512_256Hash)
	fmt.Println("length", len(sha512_256Hash))
	fmt.Println("")

	// calculate BLAKE2b-256 hash
	blake2b256Hash, _ := blake2b.New256(optionalKey)
	blake2b256Hash.Write(data)
	blake2b256Sum := blake2b256Hash.Sum(nil)
	fmt.Println("blake2b256Sum:")
	fmt.Println(blake2b256Sum)
	fmt.Printf("hex: %x\n", blake2b256Sum)
	fmt.Println("length", len(blake2b256Sum))
	fmt.Println("")

	// calculate BLAKE2b-384 hash
	blake2b384Hash, _ := blake2b.New384(optionalKey)
	blake2b384Hash.Write(data)
	blake2b384Sum := blake2b384Hash.Sum(nil)
	fmt.Println("blake2b384Sum:")
	fmt.Println(blake2b384Sum)
	fmt.Printf("hex: %x\n", blake2b384Sum)
	fmt.Println("length", len(blake2b384Sum))
	fmt.Println("")

	// calculate BLAKE2b-512 hash
	blake2b512Hash, _ := blake2b.New512(optionalKey)
	blake2b512Hash.Write(data)
	blake2b512Sum := blake2b512Hash.Sum(nil)
	fmt.Println("blake2b512Sum:")
	fmt.Println(blake2b512Sum)
	fmt.Printf("hex: %x\n", blake2b512Sum)
	fmt.Println("length", len(blake2b512Sum))
}
