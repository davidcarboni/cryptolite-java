package test

import (
	"reflect"
	"testing"

	"github.com/davidcarboni/cryptolite/bytearray"
)

var data = []byte("Mary had a little Café")

// Verifies a byte array can be correctly converted to a hex String and back again.
func TestHex(t *testing.T) {

	// Given
	// The byte slice from setup

	// When
	// We convert to hex and back again
	hex := bytearray.ToHexString(data)
	backAgain, err := bytearray.FromHexString(hex)

	// Then
	// The end result should match the input
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(data, backAgain) {
		t.Error("Hex conversion failed.")
	}

}

// Verifies a byte array can be correctly converted to base64 and back again.
func TestBase64(t *testing.T) {

	// Given
	// The byte slice from setup

	// When
	// We convert to base64 and back again
	base64 := bytearray.ToBase64String(data)
	backAgain, err := bytearray.FromBase64String(base64)

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
	unicode := bytearray.ToString(data)
	backAgain := bytearray.FromString(unicode)

	// Then
	// The end result should match the input
	if !reflect.DeepEqual(data, backAgain) {
		t.Error("String conversion failed.")
	}

}
