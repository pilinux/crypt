// Package main - example usage of the envelope encryption scheme.
package main

import (
	"fmt"

	"github.com/pilinux/crypt/envelope"
)

func main() {
	// The application secret, typically read from an env var such as
	// ENCRYPTION_SECRET. It must be at least envelope.MinSecretLength chars.
	secret := "0123456789abcdef0123456789abcdef01234567"

	// Configure the scheme with app-specific HKDF domain-separation labels.
	// Pin these in your own source; changing them orphans already-sealed data.
	scheme := envelope.New(envelope.Config{
		KEKLabel:    "myapp:kek:v1",
		SubKeyLabel: "myapp:data-subkey:v1",
	})

	// 1. Derive the key-encryption key (KEK) from the secret.
	kek, err := scheme.DeriveKEK(secret)
	if err != nil {
		fmt.Println("DeriveKEK:", err)
		return
	}

	// 2. Generate the master key once and store it wrapped (KEK-encrypted).
	masterKey, err := envelope.GenerateMasterKey()
	if err != nil {
		fmt.Println("GenerateMasterKey:", err)
		return
	}
	wrapped, err := envelope.WrapKey(kek, masterKey)
	if err != nil {
		fmt.Println("WrapKey:", err)
		return
	}
	fmt.Printf("wrapped master key (persist this): %x\n", wrapped)

	// ... later, on startup, recover the master key from storage.
	masterKey, err = envelope.UnwrapKey(kek, wrapped)
	if err != nil {
		fmt.Println("UnwrapKey:", err)
		return
	}

	// 3. Seal and open a string.
	token, err := scheme.SealString(masterKey, "attack at dawn")
	if err != nil {
		fmt.Println("SealString:", err)
		return
	}
	fmt.Println("sealed token:", token)

	plaintext, err := scheme.OpenString(masterKey, token)
	if err != nil {
		fmt.Println("OpenString:", err)
		return
	}
	fmt.Println("opened string:", plaintext)

	// 4. Seal and open a signed integer.
	intToken, err := scheme.SealInt64(masterKey, 42)
	if err != nil {
		fmt.Println("SealInt64:", err)
		return
	}
	n, err := scheme.OpenInt64(masterKey, intToken)
	if err != nil {
		fmt.Println("OpenInt64:", err)
		return
	}
	fmt.Println("opened int64:", n)

	// 5. Fingerprint a payload and mint a random file ID.
	fmt.Println("sha256:", envelope.Sha256Hex([]byte("attack at dawn")))
	id, err := envelope.RandomHex(16)
	if err != nil {
		fmt.Println("RandomHex:", err)
		return
	}
	fmt.Println("random id:", id)
}
