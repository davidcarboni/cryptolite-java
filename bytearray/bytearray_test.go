package bytearray

import (
	"reflect"
	"testing"
)

var data = []byte("Mary had a little Café")

// Verifies a byte array can be correctly converted to a hex String and back again.
func TestHex(t *testing.T) {

	// Given
	// The byte slice from setup

	// When
	// We convert to hex and back again
	hexString := ToHex(data)
	backAgain, err := FromHex(hexString)

	// Then
	// The end result should match the input
	if err != nil {
		t.Errorf("Error decoding hex: %s", hexString)
	}
	if !reflect.DeepEqual(data, backAgain) {
		t.Errorf("Hex string did not corectly convert back to bytes: %s", hexString)
	}
}

// Verifies a byte array can be correctly converted to base64 and back again.
func TestBase64(t *testing.T) {

	// Given
	// The byte slice from setup

	// When
	// We convert to base64 and back again
	base64 := ToBase64(data)
	backAgain, err := FromBase64(base64)

	// Then
	// The end result should match the input
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(data, backAgain) {
		t.Error("Base64 conversion failed.")
	}

}

// Verifies a byte array can be correctly converted to a string and back again.
func TestString(t *testing.T) {

	// Given
	// The byte slice from setup

	// When
	// We convert to string and back again
	unicode := ToString(data)
	backAgain := FromString(unicode)

	// Then
	// The end result should match the input
	if !reflect.DeepEqual(data, backAgain) {
		t.Error("String conversion failed.")
	}

}
