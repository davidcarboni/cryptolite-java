package test

import (
	"regexp"
	"testing"

	"github.com/davidcarboni/cryptolite/bytearray"
	"github.com/davidcarboni/cryptolite/random"
)

// Checks that generating a random byte array returns the expected number of bytes.
func TestByteArray(t *testing.T) {

	// Given
	length := 20

	// When
	// Some random bytes
	randomBytes := random.ByteArray(length)

	// Then
	// Check we got what we expected
	if length != len(randomBytes) {
		t.Error("Unexpected random byte lenth.")
	}
}

// Checks that the number of bits in the returned ID is the same as specified by random.TokenBits.
func testTokenLength(t *testing.T) {

	// When
	// We generate a token
	token := random.Token()

	// Then
	// It should be of the expected length
	tokenBytes, err := bytearray.FromHexString(token)
	if err != nil {
		t.Error(err)
	}
	if random.TokenBits != len(tokenBytes)*8 {
		t.Error("Unexpected token bit-length")
	}
}

// Checks that the number of bytes in a returned salt value matches the length specified in random.SaltBytes.
func TestSaltLength(t *testing.T) {

	// When
	// We generate a salt
	salt := random.Salt()

	// Then
	// It should be of the expected length
	saltBytes, err := bytearray.FromBase64String(salt)
	if err != nil {
		t.Error(err)
	}
	if random.SaltBytes != len(saltBytes) {
		t.Error("Unexpected salt byte-length")
	}
}

// Checks the number of characters and the content of the returned password matches the expected content.
func TestPassword(t *testing.T) {

	// Given
	var password string
	maxLength := 100

	for length := 1; length < maxLength; length++ {

		// When
		password = random.Password(length)

		// Then
		if length != len(password) {
			t.Error("Unexpected password length")
		}
		match, _ := regexp.MatchString("[A-Za-z0-9]+", password)
		if !match {
			t.Error("Unexpected password content")
		}
	}
}

// Test the general randomness of token generation.
//If this test fails, consider yourself astoundingly lucky.. or check the code is really producing random numbers.
func TestRandomnessOfTokens(t *testing.T) {

	iterations := 1000
	for i := 0; i < iterations; i++ {

		// When
		token1 := random.Token()
		token2 := random.Token()

		// Then
		if token1 != token2 {
			t.Error("Got identical tokens.")
		}
	}
}

// Test the general randomness of salt generation.
//If this test fails, consider yourself astoundingly lucky.. or check the code is really producing random numbers.
func TestRandomnessOfSalt(t *testing.T) {

	iterations := 1000
	for i := 0; i < iterations; i++ {

		// When
		salt1 := random.Salt()
		salt2 := random.Salt()

		// Then
		if salt1 != salt2 {
			t.Error("Got identical salts.")
		}
	}
}

// Test the general randomness of password generation.
// If this test fails, consider yourself astoundingly lucky.. or check the code is really producing random numbers.
func TestRandomnessOfPasswords(t *testing.T) {

	iterations := 1000
	passwordSize := 8
	for i := 0; i < iterations; i++ {

		// When
		password1 := random.Password(passwordSize)
		password2 := random.Password(passwordSize)

		// Then
		if password1 != password2 {
			t.Error("Got identical passwords.")
		}
	}
}
