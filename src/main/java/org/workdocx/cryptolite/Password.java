/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.lang.ArrayUtils;

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
	 * @return The password hash as a base-64 encoded String.
	 */
	public static String hash(String password) {

		// Generate a random salt:
		byte[] salt = Codec.fromBase64String(Random.generateSalt());

		// Hash the password:
		byte[] hash = hash(password, salt);

		// Concatenate the salt and hash: 
		byte[] result = ArrayUtils.addAll(salt, hash);

		// Base-64 encode the result:
		String base64 = Codec.toBase64String(result);
		return base64;
	}

	/**
	 * Verifies the given plaintext password against a value that {@link #hash(String)} produced.
	 * 
	 * @param password
	 *            A plaintext password.
	 * @param hash
	 *            A value previously produced by {@link #hash(String)}.
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
	 * This method does the actual work of hashing a plaintext password string, using
	 * {@value #ALGORITHM}.
	 * 
	 * @param password
	 *            The plaintext password.
	 * @param salt
	 *            The salt value to use in the hash.
	 * @return The hash of the password.
	 */
	private static byte[] hash(String password, byte[] salt) {

		// Get a SecretKeyFactory for ALGORITHM:
		SecretKeyFactory factory;
		try {
			// TODO: BouncyCastle only provides PBKDF2 in their JDK 1.6 releases, so try to use it, if available:
			factory = SecretKeyFactory.getInstance(ALGORITHM, SecurityProvider.getProviderName());
		} catch (NoSuchAlgorithmException e) {
			try {
				// TODO: If PBKDF2 is not available from BouncyCastle, try to use a default provider (Sun provides PBKDF2 in JDK 1.5):
				factory = SecretKeyFactory.getInstance(ALGORITHM);
			} catch (NoSuchAlgorithmException e1) {
				throw new RuntimeException("Unable to locate algorithm " + ALGORITHM, e1);
			}
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate JCE provider. Are the BouncyCastle libraries installed?", e);
		}

		// Generate the bytes for the hash by generating a key and using its encoded form:
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, HASH_SIZE);
		byte[] bytes;
		try {
			Key key = factory.generateSecret(pbeKeySpec);
			bytes = key.getEncoded();
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Error generating password-based key.", e);
		}

		return bytes;
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
