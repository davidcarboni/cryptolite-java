package com.github.davidcarboni.cryptolite;

import java.security.Key;
import java.util.Arrays;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

/**
 * 
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
	public static final String ALGORITHM = "PBKDF2WithHmacSHA1";

	/** The iteration count for the function. */
	public static final int ITERATION_COUNT = 1024;

	/** The number of bytes to use in the salt value. */
	public static final int SALT_SIZE = 16;

	/** The number of bytes to produce in the hash. */
	public static final int HASH_SIZE = 256;

	/**
	 * Produces a good hash of the given password, using {@value #ALGORITHM}, an iteration count of
	 * {@value #ITERATION_COUNT} and a random salt value of {@value #SALT_SIZE} bytes. The returned
	 * value is a concatenation of the salt value and the password hash and this should be passed as
	 * returned to {@link #verify(String, String)} along with the plaintext password.
	 * 
	 * @param password
	 *            The password to be hashed.
	 * @return The password hash as a base-64 encoded String. If the given password is null, null is
	 *         returned.
	 */
	public static String hash(String password) {

		String result = null;

		if (password != null) {

			// Generate a random salt:
			String salt = Random.generateSalt();

			// Hash the password:
			byte[] hash = hash(password, salt);

			// Concatenate the salt and hash: 
			byte[] concatenated = ArrayUtils.addAll(Codec.fromBase64String(salt), hash);

			// Base-64 encode the result:
			result = Codec.toBase64String(concatenated);
		}

		return result;
	}

	/**
	 * Verifies the given plaintext password against a value that {@link #hash(String)} produced.
	 * 
	 * @param password
	 *            A plaintext password. If this is null, false will be returned.
	 * @param hash
	 *            A value previously produced by {@link #hash(String)}. If this is empty or shorter
	 *            than expected, false will be returned.
	 * @return If the password hashes to the same value as that contained in the hash parameter,
	 *         true.
	 */
	public static boolean verify(String password, String hash) {

		boolean result = false;

		if (StringUtils.isNotBlank(hash) && password != null) {
			// Get the salt and hash from the input string:
			byte[] value = Codec.fromBase64String(hash);

			// Check the size of the value to ensure it's at least as long as the salt: 
			if (value.length >= SALT_SIZE) {

				// Extract the salt and password hash:
				String valueSalt = getSalt(value);
				byte[] valueHash = getHash(value);

				// Hash the password with the same salt in order to get the same result:
				byte[] passwordHash = hash(password, valueSalt);

				// See whether they match:
				result = Arrays.equals(valueHash, passwordHash);
			}
		}

		return result;
	}

	/**
	 * This method does the actual work of hashing a plaintext password string, using
	 * {@link Keys#generateSecretKey(char[], String, int)}.
	 * 
	 * @param password
	 *            The plaintext password.
	 * @param salt
	 *            The salt value to use in the hash.
	 * @return The hash of the password.
	 */
	private static byte[] hash(String password, String salt) {

		Key key = Keys.generateSecretKey(toCharArray(password), salt, HASH_SIZE);
		return key.getEncoded();
	}

	/**
	 * Converts the given password to a char array.
	 * <p>
	 * NB: an empty char array can cause errors when passed to
	 * {@link javax.crypto.SecretKeyFactory#generateSecret(java.security.spec.KeySpec)} in
	 * {@link Keys#generateSecretKey(char[], String, int)}, so if the password is an empty String,
	 * the return value is a char array containing a single element of value 0.
	 * 
	 * @param password
	 *            The password to be converted.
	 * @return {@link String#toCharArray()} or, if the password is an empty string
	 *         <code>new char[] {0}</code>
	 */
	private static char[] toCharArray(String password) {
		char[] result = password.toCharArray();
		if (result.length == 0) {
			result = new char[] {0};
		}
		return result;
	}

	/**
	 * Retrieves the salt from the given value.
	 * 
	 * @param value
	 *            The overall password hash value.
	 * @return The salt, which is the first {@value #SALT_SIZE} bytes of the
	 */
	private static String getSalt(byte[] value) {

		byte[] salt = new byte[SALT_SIZE];
		System.arraycopy(value, 0, salt, 0, salt.length);
		return Codec.toBase64String(salt);
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
