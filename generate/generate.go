// Package generate generates things that need to be random,
// including salt, token and password values.
package generate

import (
	"crypto/rand"

	"github.com/davidcarboni/cryptolite/bytearray"
)

// TokenBits is the length for tokens.
var TokenBits = 256

// SaltBytes is the length for salt values.
var SaltBytes = 16

// Work out the right number of bytes for random tokens:
var tokenLengthBytes = TokenBits / 8

// Characters for pasword generation:
var passwordCharacters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

// ByteArray instantiates and populates a byte array of the specified length.
//
// The length parameter sets the length of the returned slice.
func ByteArray(length int) []byte {
	byteArray := make([]byte, length)
	// rand.Read uses io.ReadFull so the slice will be fully populated if err is nil:
	_, err := rand.Read(byteArray)
	if err != nil {
		panic(err)
	}
	return byteArray
}

// Token generates a random token.
// Returns A 256-bit (32 byte) random token as a hexadecimal string.
func Token() string {
	tokenBytes := ByteArray(tokenLengthBytes)
	token := bytearray.ToHex(tokenBytes)
	return token
}

// Password generates a random password.
//
// The length parameter specifies the length of the password to be returned.
// Returns A password of the specified length, selected from passwordCharacters.
func Password(length int) string {

	result := ""
	values := ByteArray(length)
	// We use a modulus of an increasing index rather than of the byte values
	// to avoid certain characters coming up more often.
	index := 0

	for i := 0; i < length; i++ {
		index += int(values[i])
		// We're not using any complex characters, so glyph length is fine:
		index = index % len(passwordCharacters)
		result += string(passwordCharacters[index])
	}

	return result
}

// Salt generates a random salt value.
// If a salt value is needed by an API call,
// the documentation of that method should reference this method. Other than than,
// it should not be necessary to call this in normal usage of this library.
//
// Returns a random salt value of SaltBytes length, as a base64-encoded
// string (for easy storage).
func Salt() string {
	salt := ByteArray(SaltBytes)
	return bytearray.ToBase64(salt)
}
