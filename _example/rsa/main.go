// Package main - example usage of RSA encryption - decryption
package main

import (
	"fmt"

	"github.com/pilinux/crypt"
)

func main() {
	text := "Hello world"

	// public key in PEM format as a string
	publicKeyPEM := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3awVyjRX9exXCyAwqhwX
YsmNWU5teeqQWpbmnVpYiOuxHhtBzhpBvlK0Xy+8oGXEfmrznCdHG+l5763116Fz
2qHRclCzEIX7fgHgG2Jx7PC6Dm1daOgThxeTrvwfKp9NpITogI4Lfeb/AQ1KOF1Y
/MCoSSKhq40Gucoksdnv8Af21lkb7WIXKYg70ZOUKV+PxSsOKyfi4RoIJl/QGEJv
CKUy/TtV6HuNflMnmGRLKeos7JuugrGIg9/OjamUsd1EY2urNiQ+RYYk4LesQjki
fn/oCrarrfRNCMaS1Wvd1w81RPg+5px+Va0ypymq/ZjeKHDxhQgBlVyIYou+CwzG
awIDAQAB
-----END PUBLIC KEY-----
`

	// private key in PEM format as a string
	privateKeyPEM := `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdrBXKNFf17FcL
IDCqHBdiyY1ZTm156pBaluadWliI67EeG0HOGkG+UrRfL7ygZcR+avOcJ0cb6Xnv
rfXXoXPaodFyULMQhft+AeAbYnHs8LoObV1o6BOHF5Ou/B8qn02khOiAjgt95v8B
DUo4XVj8wKhJIqGrjQa5yiSx2e/wB/bWWRvtYhcpiDvRk5QpX4/FKw4rJ+LhGggm
X9AYQm8IpTL9O1Xoe41+UyeYZEsp6izsm66CsYiD386NqZSx3URja6s2JD5FhiTg
t6xCOSJ+f+gKtqut9E0IxpLVa93XDzVE+D7mnH5VrTKnKar9mN4ocPGFCAGVXIhi
i74LDMZrAgMBAAECggEAOUW/YX1xpn/YI28/M4xLfIIPq53ISkIQ5t7rGYegrUub
+OfY8iu1hbtvj9JRHW39vR3b8CHzzOHfV84t4Pb9bGT3rN3tzdyYFD/ey6R9Q9cU
cyrNgg/ID9THGuRYFxaOpG2UdrZ8gJyAkSCCZxqzJaaPNEom1CB9Nt5j6bGhvPWO
sccx+yrgtrQeCFwXAvj6kk3eRyAHBq4yCFDoDLy4RBZ2ZMUe6uT0ku4T7trOf1B1
qU8wLykXTCKeTknIo6FB8Foj0t52jCa3iKg4gJVsKEh7SsRy0O6Tvatrkxgm3i+M
wETzpPEGTSC4W9HbnYiNmn4uP0DeZDs3TmWiWZcVKQKBgQDy2VOvt8Ak9itPf6bq
6EjdP/UlzzSEHKLbh6bYMTWaXB49v6XRxd7Wqk2jHob7ZL3mhWzogoQG0IpaGaS2
HrWebth2tbajXh9TSMxQVGidBRkIRNBsaQEkhzPG+UXmAZJxFOBkilA+OeAvUfFX
W8Jse8wOcBAbh/jC1Hy45/KfKQKBgQDprS4gVH4IdkBYTJnL8Yp8AzolskwhdRSk
OZ+pU+L9QX9Sv0X7B5bRfAcL61fOijuVTeYRJMit/N+JSdQY2/vkrJ2arLy3PCOJ
eni3zTgsL80ZX0LsqWavs+jCKTaXg6Co01IhQSRPb9LTkHPSAye6fmBIF4tbsrpX
eQtbibjvcwKBgEFJohEEknidYclupR5UMnqg3jQ6/4Bg/nuMfZNzr1h/WXX6VwcN
bjpB8Ltg0qM1U0RtLHlZ1UrLt9Y/PKPln6gnXrSTZ7WF8V//m0YhWzqTi0ZI0cvD
cxYx7v6YN219kLQsC6Ob97Sy9I1kN0DoH13w7kwXXo04Qe2HGLzRRs35AoGBALkV
v5RB+DWxnBOUULj1zy+cysCy8ZQKjVfqgGj5FbBs4XFkKQTFJRM1/srVFI52dO00
b0ci8ITG5zNxs7og++pLQuYRbcRgsPEifV1wAc8V6YjwKC0VnE0M3g5z4FawHl+6
SbInS6BTvRRvtR0h/KS9lntjkrEF5oyERpexhTa7AoGATP9+QU1L7+DN0YTtZsNm
eHcwyhZv1wU8umpgBDSP0ZWxkbeOOlmWlkwtvsw4cwbZsieUvwBvHgmS4ODZmCu7
1fcMzN6SDVLYLOc0coINyBY6/CNMp/sdYJ0qxiSfuFkQAOj5kvzkfSbRw8Bn+OVD
a6bLS9Kl4jLdVtF+OR5VFiY=
-----END PRIVATE KEY-----
`

	// RSA: encryption
	// Encoder
	encoder := crypt.NewEncoder(publicKeyPEM)
	if encoder.Err != nil {
		fmt.Println(encoder.Err)
		return
	}
	encoder.HashAlg = crypt.SHA512
	encryptedData, err := encoder.EncryptRSA(text)
	if err != nil {
		fmt.Println(err)
		return
	}

	ciphertext := encoder.ToBase64RawStd([]byte(encryptedData))
	fmt.Println("ciphertext encoded into base64:")
	fmt.Println(ciphertext)
	fmt.Println("")

	// RSA: decryption
	// Decoder
	decoder := crypt.NewDecoder(privateKeyPEM)
	if decoder.Err != nil {
		fmt.Println(decoder.Err)
		return
	}
	decoder.HashAlg = crypt.SHA512
	decodedText, err := decoder.FromBase64RawStd(ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	plaintext, err := decoder.DecryptRSA(decodedText)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("plaintext:")
	fmt.Println(plaintext)
	fmt.Println("")
}
