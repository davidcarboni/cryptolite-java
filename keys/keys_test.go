// Tests for byte array conversions.
package keys_test

import (
	"testing"

	"github.com/davidcarboni/cryptolite/bytearray"
	"github.com/davidcarboni/cryptolite/keys"
)

// Verifies arbitrary byte arrays can be correctly converted to a hex String and back again.
func TestGenerateSecretKey(t *testing.T) {

	// Given
	// A known password/salt -> key vector
	password := "Mary had a little Café"
	salt := "EvwdaavC8dRvR4RPaI9Gkg=="
	keyHex := "e73d452399476f0488b32b0bea2b8c0da35c33b122cd52c6ed35188e4117f448"

	// When
	// We generate the key
	key := keys.GenerateSecretKey(password, salt)

	// Then
	// We should get the expected key
	if bytearray.ToHex(key) != keyHex {
		t.Error("Unable to generate the expected key.")
	}
}
