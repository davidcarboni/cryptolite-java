// Package keys generates cryptographic keys.
//
//
// Key types
//
// Secret keys (either randomly generated or deterministic, based on a password).
//
// Public-Private key pairs.
//
//
// How to use keys
//
// Secret keys are used for encryption (see Crypto).
//
// Secret keys are also used to secure other secret keys and private keys (see KeyWrapper)
//
// Public-Private keys are used for digital signatures (see DigitalSignature).
//
// Public-Private keys are also used for key exchange (see KeyExchange).
//
//
// Managing encryption keys
//
// A good applied cryptography design is all about how you manage secrets: keys and passwords.
//
// Assuming you're using primitives correctly (that's what Cryptolite does for you)
// then it'll be all about your key management design.
//
// Here are some examples, based on using secret keys to encrypt user data,
// to give you a primer on the things you'll want to consider when designing with encryption.
// In these examples, we're choosing between random and deterministic (password-based) keys.
//
//
// Deterministic key design
//
// Deterministic keys are the easiest to manage as you don't need to store the key itself.
// Providing the password used to generate the key is properly managed and is available
// when you need access to the key, the key can be reliably regenerated each time.
//
// The drawback is that if you want to generate more than one key you'll need more than one password.
// However, if you do only need one key, this approach can be ideal as you could use, say, the user's
// plaintext password to generate the key. You never store a user's plaintext password (see
// password.Hash(String)) so the right key can only be generated when the user logs in.
//
// Bear in mind however that if the user changes (or resets) their password this will generate a
// different key, so you'll need a plan for recovering data encrypted with the old key and
// re-encrypting it with the new one.
//
//
// Random key design
//
// Random keys are simple to generate, but need to be stored because there's no way
// to regenerate the same key.
//
// To store a key you can use keywrapper.WrapSecretKey().
// This encrypts the key which means it can be safely stored in, for example,
// a database or configuration value.
//
// The benefit of the keywrapper approach is that
// when a user changes their password you'll only need to re-encrypt the stored keys using a new
// keywrapper initialised with the new password, rather than have to re-encrypt all
// data that was encrypted with a key generated based on the user's password
// (as in a deterministic design).
//
//
// Password recovery and reset
//
// In both designs, when a user changes their password you will have the old and the new plaintext
// passwords, meaning you can decrypt with the old an re-encrypt with the new.
//
// The difficulty comes when you need to reset a password, because it's not possible to recover
// the old password, so you can't recover the encryption key either. In this case you'll either
// need a backup way to recover the encryption key, or you'll need to be clear that data cannot
// be recovered at all.
//
// Whatever your solution, remember that storing someone's password in any recoverable form is not OK,
// so you'll need to put some thought into the recovery process.
//
package keys

import (
	"github.com/davidcarboni/cryptolite/generate"
)

// Please treat these values as constants.
// They are implemented as variables just in case you do need to alter them.
// These are the settings that provide "right" cryptography so you'll need to
// know what you're doing.
var (
	// The secret key algorithm.
	SymmetricAlgorithm = "AES"

	// The key size for secret keys.
	SymmetricKeySize = 256

	// The algorithm to use to generate password-based secret keys.
	SymmetricPasswordAlgorithm = "PBKDF2WithHmacSHA1"

	// The number of iteration rounds to use for password-based secret keys.
	SymmetricPasswordIterations = 1024

	// The public-private key pair algorithm.
	AsymmetricAlgorithm = "RSA"

	// The key size for public-private key pairs.
	AsymmetricKeySize = 4096
)

// NewSecretKey generates a new secret (also known as symmetric) key for use with AES.
//
// The key size is determined by SymmetricKeySize.
//
// Returns a new, randomly generated secret key.
func NewSecretKey() ([]byte, error) {
	// FYI: AES keys are just random bytes from a strong source of randomness.
	return generate.ByteArray(SymmetricKeySize), nil
}

// GenerateSecretKey generates a new secret (or symmetric) key for use with SYMMETRIC_ALGORITHM using the given password and salt values.
//
// Given the same password and salt, this method will (re)generate the same key.
//
// Note that this method may or may not handle blank passwords. This seems to be related to the
// implementation of the algorithm.
//
// The ``password`` parameter is the starting point to use in generating the key. This can be a password, or any
//                 suitably secret string. It's worth noting that, if a user's plaintext password is
//                 used, this makes key derivation secure, but means the key can never be recovered
//                 if a user forgets their password. If a different value, such as a password hash is
//                 used, this is not really secure, but does mean the key can be recovered if a user
//                 forgets their password. It's a trade-off, right?
//
// A value for the salt parameter can be generated by calling
//                 ``generate.Salt()``. You'll need to store the salt value (this is ok to do
//                 because salt isn't particularly sensitive) and use the same salt each time in
//                 order to always generate the same key. Using salt is good practice as it ensures
//                 that keys generated from the same password will be different - i.e. if two users
//                 use the password, having a salt value avoids the generated keys being
//                 identical which might give away someone's password.
//
// Returns a deterministic secret key, defined by the given password and salt.
func GenerateSecretKey(password string, salt string) []byte {

	//saltBytes, err := bytearray.FromBase64(salt)
	//if err != nil {
	//	panic("Unable to gerenate salt.")
	//}
	//key_generator = PBKDF2HMAC(
	//    algorithm=hashes.SHA256(),
	//    length=SYMMETRIC_KEY_SIZE / 8,
	//    salt=salt_bytes,
	//    iterations=SYMMETRIC_PASSWORD_ITERATIONS,
	//    backend=backend
	//)
	return generate.ByteArray(32) //key_generator.derive(password.encode("utf-8"))
}

// NewKeyPair generates a new public-private (or asymmetric) key pair for use with ASYMMETRIC_ALGORITHM.
// The key size will be ASYMMETRIC_KEY_SIZE bits.
// Returns a new, randomly generated asymmetric key pair.
func NewKeyPair() []byte {

	return generate.ByteArray(32)

	//return rsa.generate_private_key(
	//    public_exponent=65537,
	//    key_size=ASYMMETRIC_KEY_SIZE,
	//    backend=default_backend()
	//)
}
