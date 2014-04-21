package com.github.davidcarboni.cryptolite;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.lang.RandomStringUtils;

/**
 * This class provides random functions, such as Salt, ID and password
 * generation. It also allows you to get a singleton {@link SecureRandom}
 * instance.
 * 
 * @author David Carboni
 * 
 */
public class Random {

	/** The length of IDs: {@value #ID_BITS}. */
	public static final int ID_BITS = 256;

	/**
	 * The algorithm for the {@link SecureRandom} instance: {@value #ALGORITHM}.
	 */
	public static final String ALGORITHM = "SHA1PRNG";

	/** The length of salt values: {@value #SALT_BYTES}. */
	public static final int SALT_BYTES = 16;

	// Work out the right number of bytes for random IDs:
	private static final int bitsInAByte = 8;
	private static final int idLengthBytes = ID_BITS / bitsInAByte;

	/** Lazily-instantiated, cached {@link SecureRandom} instance. */
	private static SecureRandom secureRandom;

	/**
	 * 
	 * @return A lazily-instantiated, cached {@link SecureRandom} instance for
	 *         the algorithm {@value #ALGORITHM}. This is a global instance and
	 *         is thread-safe. The only consideration is whether thread
	 *         contention could be an issue. See
	 *         http://stackoverflow.com/questions
	 *         /1461568/is-securerandom-thread-safe for more details.
	 */
	public static SecureRandom getInstance() {

		// Create if necessary:
		if (secureRandom == null) {
			// NB according to the javadoc, getInstance produces an appropriate
			// SecureRandom, which will be seeded on the first call to
			// nextBytes():
			// "Note that the returned instance of SecureRandom has not been
			// seeded. A call to the setSeed method will seed the SecureRandom
			// object.
			// If a call is not made to setSeed, the first call to the nextBytes
			// method will force the SecureRandom object to seed itself."
			try {
				secureRandom = SecureRandom.getInstance(ALGORITHM);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("Unable to find algorithm " + ALGORITHM + " for "
						+ SecureRandom.class.getSimpleName());
			}
		}

		return secureRandom;
	}

	/**
	 * @return A 256-bit (32 byte) random ID as a hexadecimal string.
	 */
	public static String generateId() {

		byte[] bytes = new byte[idLengthBytes];

		getInstance().nextBytes(bytes);

		return Codec.toHexString(bytes);
	}

	/**
	 * Convenience method to generate a random password using Apache
	 * {@link RandomStringUtils#random(int, int, int, boolean, boolean, char[], java.util.Random)}
	 * , providing the {@link SecureRandom} returned by {@link #getInstance()}
	 * as the last parameter.
	 * 
	 * @param length
	 *            The length of the password to be returned.
	 * @return A String of the specified length, composed of uppercase letters,
	 *         lowercase letters and numbers.
	 */
	public static String generatePassword(int length) {
		return RandomStringUtils.random(length, 0, 0, true, true, null, getInstance());
	}

	/**
	 * Generates a random salt value. If a salt value is needed by an API call,
	 * the JavaDoc of that method should reference this method. Other than than,
	 * it should not be necessary to call this in normal usage of this library.
	 * 
	 * @return A {@value #SALT_BYTES}-byte random salt value as a base64-encoded
	 *         string (for easy storage).
	 */
	public static String generateSalt() {

		byte[] salt = new byte[SALT_BYTES];

		getInstance().nextBytes(salt);

		return Codec.toBase64String(salt);
	}
}
