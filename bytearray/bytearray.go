//Package bytearray provides the ability to convert byte arrays to
// Strings, Base-64 and hexadecimal and vice-versa.
//
// Cryptography is mainly about manipulating byte arrays, so this package provides
// the different translations you need:
//
// - Plain-text strings need to be converted to a byte array for encryption
// and, after decryption, need to be converted from a byte array back to a
// String.
//
// - Encrypted byte arrays look like random bytes, which means they can't be
// reliably represented as a String. The simplest way to represent arbitrary bytes
// as a String is using Base-64. This class lets you convert a byte array of
// encrypted data to Base-64 so it can be easily stored and back again so it can
// be decrypted.
//
// - Finally, this class also allows you to transform a byte array to a
// hexadecimal String and back again. This is most useful in development when
// you need to print out values to see what's going on. Conversion from
// hexadecimal to byte array is occasionally useful, but chances are you'll use
// byte[] to hex most of the time.
//
// The naming convention for functions is set up from the point of view of
// a byte array. For example, a byte array can go:
//  ToHexString
// and back:
//  FromHexString
// The same pattern is usef for each pair of methods (to/from hex, base64 and string).
package bytearray

import (
	b64 "encoding/base64"
	hx "encoding/hex"
)

// ToHexString renders the given byte array as a hex String.
//
// This is a convenience method useful for checking values during development.
//
// Internally, this checks for null and then calls hex.EncodeToString.
//
// The bytes parameter is encoded as a hex string representation.
func ToHexString(bytes []byte) string {
	return hx.EncodeToString(bytes)
}

// FromHexString converts the given hex string to a byte array.
//
// The hex parameter is parsed to bytes.
func FromHexString(hex string) ([]byte, error) {
	return hx.DecodeString(hex)
}

// ToBase64String encodes the given byte array as a base-64 String.
//
// Internally, this checks for null and then calls the Apache commons-codec
// method base64.b64encode(bytetarray).
// The bytes parameter is returned encoded using base-64.
func ToBase64String(bytes []byte) string {
	return b64.StdEncoding.EncodeToString(bytes)
}

// FromBase64String decodes the given base-64 string into a byte array.
//
// The base64 parameter is decoded to a byte slice.
func FromBase64String(base64 string) ([]byte, error) {
	return b64.StdEncoding.DecodeString(base64)
}

// ToString converts the given byte array to a String.
//
// The bytes parameter is converted to the String represented by the given bytes.
func ToString(bytes []byte) string {
	return string(bytes)
}

// FromString converts the given String to a byte array.
//
// The string parameter is converted to a byte array.
func FromString(unicode string) []byte {
	return []byte(unicode)
}
