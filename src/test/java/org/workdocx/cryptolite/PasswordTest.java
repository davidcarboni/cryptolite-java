/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 
 * Test for {@link Password}.
 * 
 * @author David Carboni
 * 
 */
public class PasswordTest {

	/**
	 * Test method for {@link org.workdocx.cryptolite.Password#hash(java.lang.String)}.
	 */
	@Test
	public void testHash() {
		// Given
		String password = "testHash";

		// When
		String hash = Password.hash(password);

		// Then
		// Simplistic check to ensure the password hasn't just been returned unaltered
		assertFalse(hash.equals(password));
	}

	/**
	 * Test method for {@link org.workdocx.cryptolite.Password#hash(java.lang.String)}. Checks that
	 * two hashes of the same password are different thanks to a random salt value.
	 */
	@Test
	public void testHashDifferently() {

		// Given
		String password = "testHashDifferently";

		// When
		String hash1 = Password.hash(password);
		String hash2 = Password.hash(password);

		// Then
		assertFalse(hash1.equals(hash2));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Password#verify(java.lang.String, java.lang.String)}. Checks
	 * that a password can be verified against its hash.
	 */
	@Test
	public void testVerify() {

		// Given
		String password = "testVerify";
		String hash = Password.hash(password);

		// When
		boolean result = Password.verify(password, hash);

		// Then
		assertTrue(result);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Password#verify(java.lang.String, java.lang.String)} where the
	 * hash value is shorter that the size of the salt. This checks that we get a polite refusal
	 * rather than an exception.
	 */
	@Test
	public void testVerifyTooShort() {

		// Given
		String password = "testVerifyTooShort";
		String hash = "too short";
		assertTrue(Codec.toByteArray(hash).length <= Password.SALT_SIZE);

		// When
		boolean result = Password.verify(password, hash);

		// Then
		assertFalse(result);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Password#verify(java.lang.String, java.lang.String)}. Checks
	 * that an incorrect password doesn't verify.
	 */
	@Test
	public void testVerifyFail() {

		// Given
		String password = "testVerifyFail";
		String incorrect = "testVerifyFailz";
		// Note we add 
		String hash = Password.hash(password);

		// When
		boolean result = Password.verify(incorrect, hash);

		// Then
		assertFalse(result);
	}

}
