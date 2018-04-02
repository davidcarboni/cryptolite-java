package bytearray

import (
	"reflect"
	"testing"
)

var data = []byte("Mary had a little Café")

// Verifies a byte array can be correctly converted to a hex String and back again.
func TestHex(t *testing.T) {

	// Given
	// The byte array from setup

	// When
	// We convert to hex and back again
	hexString := ToHexString(data)
	backAgain, err := FromHexString(hexString)

	// Then
	// The end result should match the input
	if err != nil {
		t.Errorf("Error decoding hex: %s", hexString)
	}
	if !reflect.DeepEqual(data, backAgain) {
		t.Errorf("Hex string did not corectly convert back to bytes: %s", hexString)
	}
}
