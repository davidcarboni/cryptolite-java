// Tests for byte array conversions.
package bytearray_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/davidcarboni/cryptolite/generate"

	"github.com/davidcarboni/cryptolite/bytearray"
)

// Verifies arbitrary byte arrays can be correctly converted to a hex String and back again.
func TestHex(t *testing.T) {

	// Given
	data := generate.ByteArray(100)

	// When
	// We convert to hex and back again
	hexString := bytearray.ToHex(data)
	backAgain, err := bytearray.FromHex(hexString)

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
	data := generate.ByteArray(100)

	// When
	// We convert to base64 and back again
	base64 := bytearray.ToBase64(data)
	backAgain, err := bytearray.FromBase64(base64)

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
	data := []byte("Mary had a little Café")

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

// Converting a slice of byte to hex and back again.
func ExampleToHex() {
	bytes := []byte{74, 226, 4, 102, 129, 229, 107, 23}
	fmt.Printf("Bytes: %v\n", bytes)
	hex := bytearray.ToHex(bytes)
	fmt.Printf("To hex: %v\n", hex)
	back, _ := bytearray.FromHex(hex)
	fmt.Printf("And back: %v\n", back)
	// Output:
	// Bytes: [74 226 4 102 129 229 107 23]
	// To hex: 4ae2046681e56b17
	// And back: [74 226 4 102 129 229 107 23]

}

// Converting a slice of byte to hex and back again.
func ExampleFromHex() {
	bytes := []byte{195, 167, 163, 5, 150, 6, 104, 14}
	fmt.Printf("Bytes: %v\n", bytes)
	hex := bytearray.ToHex(bytes)
	fmt.Printf("To hex: %v\n", hex)
	back, _ := bytearray.FromHex(hex)
	fmt.Printf("And back: %v\n", back)
	// Output:
	// Bytes: [195 167 163 5 150 6 104 14]
	// To hex: c3a7a3059606680e
	// And back: [195 167 163 5 150 6 104 14]
}

// Converting a slice of byte to base64 and back again.
func ExampleToBase64() {
	bytes := []byte{101, 169, 133, 24, 200, 186, 51, 4}
	fmt.Printf("Bytes: %v\n", bytes)
	base64 := bytearray.ToBase64(bytes)
	fmt.Printf("To base64: %v\n", base64)
	back, _ := bytearray.FromBase64(base64)
	fmt.Printf("And back: %v\n", back)
	// Output:
	// Bytes: [101 169 133 24 200 186 51 4]
	// To base64: ZamFGMi6MwQ=
	// And back: [101 169 133 24 200 186 51 4]
}

// Converting a slice of byte to base64 and back again.
func ExampleFromBase64() {
	bytes := []byte{210, 28, 117, 111, 213, 188, 217, 23}
	fmt.Printf("Bytes: %v\n", bytes)
	base64 := bytearray.ToBase64(bytes)
	fmt.Printf("To base64: %v\n", base64)
	back, _ := bytearray.FromBase64(base64)
	fmt.Printf("And back: %v\n", back)
	// Output:
	// Bytes: [210 28 117 111 213 188 217 23]
	// To base64: 0hx1b9W82Rc=
	// And back: [210 28 117 111 213 188 217 23]

}

// Converting a slice of byte to a string and back again.
func ExampleToString() {
	bytes := []byte("Hello, 世界")
	fmt.Printf("Bytes: %v\n", bytes)
	str := bytearray.ToString(bytes)
	fmt.Printf("To string: %v\n", str)
	back := bytearray.FromString(str)
	fmt.Printf("And back: %v\n", back)
	// Output:
	// Bytes: [72 101 108 108 111 44 32 228 184 150 231 149 140]
	// To string: Hello, 世界
	// And back: [72 101 108 108 111 44 32 228 184 150 231 149 140]

}

// Converting a slice of byte to a string and back again.
func ExampleFromString() {
	bytes := []byte("Mary had a little Café")
	fmt.Printf("Bytes: %v\n", bytes)
	str := bytearray.ToString(bytes)
	fmt.Printf("To string: %v\n", str)
	back := bytearray.FromString(str)
	fmt.Printf("And back: %v\n", back)
	// Output:
	// Bytes: [77 97 114 121 32 104 97 100 32 97 32 108 105 116 116 108 101 32 67 97 102 195 169]
	// To string: Mary had a little Café
	// And back: [77 97 114 121 32 104 97 100 32 97 32 108 105 116 116 108 101 32 67 97 102 195 169]

}
