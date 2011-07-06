package org.workdocx.cryptolite;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * This class generates cryptographic keys.
 * <p>
 * The following key types are available:
 * <ul>
 * <li>Symmetric {@value #SYMMETRIC_ALGORITHM} keys of length {@value #SYMMETRIC_KEY_SIZE}</li>
 * <li>Asymmetric {@value #ASYMMETRIC_ALGORITHM} keys of length {@value #ASYMMETRIC_KEY_SIZE}</li>
 * <li>Key-wrapping keys using {@value #WRAP_ALGORITHM}, of length {@value #WRAP_KEY_SIZE}</li>
 * </ul>
 * This class also provides functionality for "wrapping" and "unwrapping" keys so that they can be
 * safely stored. NB there is an exception to this, which is that it's not really helpful to wrap a
 * key used to wrap other keys, as this requires a further wrapping key. Wrap keys are therefore
 * generated directly as a base64-encoded String and need to be managed appropriately. This is
 * always a tricky question. The answer may be to implement a password-based key derivation
 * function, such as PBKDF2, once Cryptolite moves to JDK 1.6.
 * 
 * @author David Carboni
 * 
 */
public class Keys {

	/** The symmetric encryption algorithm: {@value #SYMMETRIC_ALGORITHM}. */
	public static final String SYMMETRIC_ALGORITHM = "AES";

	/** The key size for symmetric keys: {@value #SYMMETRIC_KEY_SIZE}. */
	public static final int SYMMETRIC_KEY_SIZE = 128;

	/** The asymmetric encryption algorithm: {@value #ASYMMETRIC_ALGORITHM}. */
	public static final String ASYMMETRIC_ALGORITHM = "RSA";

	/** The key size for asymmetric keys: {@value #ASYMMETRIC_KEY_SIZE}. */
	public static final int ASYMMETRIC_KEY_SIZE = 1024;

	/**
	 * This method generates a new secret (or symmetric) key for the {@value #SYMMETRIC_ALGORITHM}
	 * algorithm with a key size of {@value #SYMMETRIC_KEY_SIZE} bits.
	 * 
	 * @return A new, randomly generated {@link SecretKey}.
	 */
	public static SecretKey newSecretKey() {

		// Get a key generator instance
		KeyGenerator keyGenerator;
		try {
			keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM, SecurityProvider.getProviderName());
			keyGenerator.init(SYMMETRIC_KEY_SIZE, Random.getInstance());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate algorithm " + SYMMETRIC_ALGORITHM, e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate JCE provider. Are the BouncyCastle libraries installed?", e);
		}

		// Generate a key:
		SecretKey result = keyGenerator.generateKey();

		return result;
	}

	/**
	 * This method generates a new public-private (or asymmetric) key pair, using the
	 * {@value #ASYMMETRIC_ALGORITHM} algorithm and a key size of {@value #ASYMMETRIC_KEY_SIZE}
	 * bits.
	 * <p>
	 * BouncyCastle will automatically generate a "Chinese Remainder Theorem" or CRT key, which
	 * makes using a symmetric encryption significantly faster.
	 * 
	 * @return A new, randomly generated asymmetric {@link KeyPair}.
	 */
	public static KeyPair newKeyPair() {

		// Construct a key generator
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM, SecurityProvider.getProviderName());
			keyPairGenerator.initialize(ASYMMETRIC_KEY_SIZE, Random.getInstance());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate algorithm " + ASYMMETRIC_ALGORITHM, e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate provider. Are the BouncyCastle libraries installed?", e);
		}

		// Generate a key:
		KeyPair result = keyPairGenerator.generateKeyPair();

		return result;
	}

}
