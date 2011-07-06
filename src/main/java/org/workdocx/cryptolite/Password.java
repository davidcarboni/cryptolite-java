package org.workdocx.cryptolite;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * This class provides password hashing and verification. The returned hashes consist of the
 * password hash, prepended with a random salt value. In order to verify a password, the plaintext
 * password should be passed to {@link #verify(String, String)} along with the stored value
 * originally produced by {@link #hash(String)}.
 * <p>
 * This password hashing and verification is done in the same way as Jasypt, but uses
 * {@value #ALGORITHM}, rather than MD5.
 * 
 * @author David Carboni
 * 
 */
public class Password {

	/** The password hashing function. */
	public static final String ALGORITHM = "SHA-512";

	/** The iteration count for the function. */
	public static final int ITERATION_COUNT = 1024;

	/** The number of bytes to use in the salt value. */
	public static final int SALT_SIZE = 16;

	//
	// Once we migrate to 1.6, switch to PBKDF2 - but remember that user accounts will need to be migrated on next login, 
	// (can't recover and re-hash passwords, so we have to wait until the user logs in) so we will have to keep old 
	// capabilities around as long as there are accounts that use them.
	//
	// public static final String ALGORITHM = "PBKDF2";// ?WithHmacSHA1 - See "Cryptographic Right Answers" via Google. 
	//

	/**
	 * Produces a good hash of the given password, using {@value #ALGORITHM}, an iteration count of
	 * {@value #ITERATION_COUNT} and a random salt value of {@value #SALT_SIZE} bytes. The returned
	 * value is a concatenation of the salt value and the password hash and this should be passed as
	 * returned to {@link #verify(String, String)} along with the plaintext password.
	 * 
	 * @param password
	 *            The password to be hashed.
	 * @return The password hash as a base-64 encoded String.
	 */
	public static String hash(String password) {

		// Generate a random salt:
		byte[] salt = new byte[SALT_SIZE];
		Random.getInstance().nextBytes(salt);

		// Hash the password:
		byte[] hash = hash(password, salt);

		// Concatenate the salt and hash: 
		byte[] result = concatenate(salt, hash);

		// Base-64 encode the result:
		String base64 = Codec.toBase64String(result);
		return base64;
	}

	/**
	 * Verifies the given plaintext password against a value that {@link #hashPassword(String)}
	 * produced.
	 * 
	 * @param password
	 *            A plaintext password.
	 * @param hash
	 *            A value previously produced by {@link #hashPassword(String)}.
	 * @return If the password hashes to the same value as that contained in the hash parameter,
	 *         true.
	 */
	public static boolean verify(String password, String hash) {

		// Get the salt and hash from the input string:
		byte[] value = Codec.fromBase64String(hash);

		// Check the size of the value to ensure it's at least as long as the salt: 
		if (value.length <= SALT_SIZE) {
			return false;
		}

		// Extract the salt and password hash:
		byte[] valueSalt = getSalt(value);
		byte[] valueHash = getHash(value);

		// Hash the password with the same salt in order to get the same result:
		byte[] passwordHash = hash(password, valueSalt);

		// See whether they match:
		return Arrays.equals(valueHash, passwordHash);
	}

	/**
	 * This method does the actual work of hashing a plaintext password string.
	 * 
	 * @param password
	 *            The plaintext password.
	 * @param salt
	 *            The salt value to use in the hash.
	 * @return The hash of the password.
	 */
	private static byte[] hash(String password, byte[] salt) {

		// Get a message digest instance:
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(ALGORITHM, SecurityProvider.getProviderName());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate password hashing algorithm: " + ALGORITHM, e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate provider " + SecurityProvider.getProviderName()
					+ " is the BouncyCastle library installed?", e);
		}

		// Digest the password and salt:
		byte[] bytes = Codec.toByteArray(password);
		digest.update(salt);
		digest.update(bytes);

		// Now iterate:
		for (int i = 1; i < ITERATION_COUNT; i++) {
			digest.update(digest.digest());
		}

		return digest.digest();
	}

	/**
	 * Concatenates two arrays.
	 * <p>
	 * see: http://stackoverflow.com/questions/80476/how-to-concatenate-two-arrays-in-java
	 * <p>
	 * This could have been done with commons-lang, but doing it directly saves a dependency and
	 * potential dependency conflict. Probably worth e.g. using a version-range dependency
	 * 
	 * @param salt
	 *            The salt value to be concatenated.
	 * @param hash
	 *            The hash value to be concatenated.
	 * @return The two arrays as a single byte array.
	 */
	private static byte[] concatenate(byte[] salt, byte[] hash) {

		byte[] result = new byte[salt.length + hash.length];
		System.arraycopy(salt, 0, result, 0, salt.length);
		System.arraycopy(hash, 0, result, salt.length, hash.length);
		return result;
	}

	/**
	 * Retrieves the salt from the given value.
	 * 
	 * @param value
	 *            The overall password hash value.
	 * @return The salt, which is the first {@value #SALT_SIZE} bytes of the
	 */
	private static byte[] getSalt(byte[] value) {

		byte[] salt = new byte[SALT_SIZE];
		System.arraycopy(value, 0, salt, 0, salt.length);
		return salt;
	}

	/**
	 * Retrieves the hash from the given value.
	 * 
	 * @param value
	 *            The overall password hash value.
	 * @return The salt, which is the first {@value #SALT_SIZE} bytes of the
	 */
	private static byte[] getHash(byte[] value) {

		byte[] hash = new byte[value.length - SALT_SIZE];
		System.arraycopy(value, SALT_SIZE, hash, 0, hash.length);
		return hash;
	}

}
