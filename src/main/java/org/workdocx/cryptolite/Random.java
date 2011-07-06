/**
 * 
 */
package org.workdocx.cryptolite;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author david
 * 
 */
public class Random {

	/** IDs are {@value #ID_BITS}-bit random numbers. */
	public static final int ID_BITS = 256;

	/** The algorithm for the {@link SecureRandom} instance: {@value #ALGORITHM}. */
	public static final String ALGORITHM = "SHA1PRNG";

	/** The length of salt values. */
	public static final int SALT_BYTES = 16;

	// Work out the right number of bytes for random IDs:
	private static final int bitsInAByte = 8;
	private static final int idLengthBytes = ID_BITS / bitsInAByte;

	/** Lazily-instantiated, cached {@link SecureRandom} instance. */
	private static SecureRandom secureRandom;

	/**
	 * 
	 * @return A lazily-instantiated, cached {@link SecureRandom} instance for the algorithm
	 *         {@value #ALGORITHM}.
	 */
	public static SecureRandom getInstance() {

		// Create if necessary:
		if (secureRandom == null) {
			// NB according to the javadoc, getInstance produces an appropriate SecureRandom, which will be seeded on the first call to nextBytes():
			// "Note that the returned instance of SecureRandom has not been seeded. A call to the setSeed method will seed the SecureRandom object. 
			//  If a call is not made to setSeed, the first call to the nextBytes method will force the SecureRandom object to seed itself."
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
	 * Generates a random salt value. If a salt value is needed by an API call, the JavaDoc of that
	 * method should reference this method. Other than than, it should not be necessary to call this
	 * in normal usage of this library.
	 * 
	 * @return A {@value #SALT_BYTES}-byte random salt value as a base64-encoded string (for easy
	 *         storage).
	 */
	public static String generateSalt() {

		byte[] salt = new byte[SALT_BYTES];

		getInstance().nextBytes(salt);

		return Codec.toBase64String(salt);
	}
}
