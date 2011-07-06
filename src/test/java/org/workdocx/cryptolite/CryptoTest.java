/*
 * Copyright (c) 2010 WorkDocX Ltd.
 * 
 * All rights reserved.
 * 
 * This software is the confidential and proprietary information of WorkDocX Ltd.
 * ("Confidential Information"). You shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement you entered into with WorkDocX.
 */
package org.workdocx.cryptolite;

import javax.crypto.SecretKey;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

/**
 * Test for {@link Crypto}.
 * 
 * @author David Carboni
 * 
 */
public class CryptoTest {

	private Crypto crypto;
	private SecretKey key;

	/**
	 * Gets a {@link Crypto} instance and a {@link SecretKey} instance.
	 */
	@Before
	public void setUp() {
		crypto = new Crypto();
		key = Keys.newSecretKey();
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
	 */
	@Test
	public void testEncryptStringSecretKey() {

		// Given
		String plaintext = "The quick brown fox & jumped over the £azy dog.";

		// When
		String ciphertext = crypto.encrypt(plaintext, key);

		// Then
		Assert.assertEquals(plaintext, crypto.decrypt(ciphertext, key));
		Assert.assertFalse(plaintext.equals(ciphertext));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}
	 * where the plaintext is an empty string.
	 * 
	 */
	@Test
	public void testEncryptStringSecretKeyEmpty() {

		// Given
		String plaintext = "";

		// When
		String ciphertext = crypto.encrypt(plaintext, key);

		// Then
		// An encrypted blank is not a blank string as there is at least an initialisation vector.
		Assert.assertEquals(plaintext, crypto.decrypt(ciphertext, key));
		Assert.assertFalse(plaintext.equals(ciphertext));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}
	 * where the plaintext is null.
	 */
	@Test
	public void testEncryptStringSecretKeyNull() {

		// Given
		String plaintext = null;

		// When
		String ciphertext = crypto.encrypt(plaintext, key);

		// Then
		Assert.assertNull(ciphertext);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
	 */
	@Test
	public void testDecryptStringSecretKey() {

		// Given
		String plaintext = "The quick brown fox & jumped over the £azy dog.";
		String ciphertext = crypto.encrypt(plaintext, key);

		// When
		String recovered = crypto.decrypt(ciphertext, key);

		// Then
		Assert.assertEquals(plaintext, recovered);
		Assert.assertFalse(ciphertext.equals(recovered));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}
	 * where the ciphertext is an empty string.
	 */
	@Test
	public void testDecryptStringSecretKeyEmpty() {

		// Given
		String ciphertext = "";

		// When
		String recovered = crypto.decrypt(ciphertext, key);

		// Then
		Assert.assertEquals("", recovered);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}
	 * where the ciphertext is null.
	 */
	@Test
	public void testDecryptStringSecretKeyNull() {

		// Given
		String ciphertext = null;

		// When
		String recovered = crypto.decrypt(ciphertext, key);

		// Then
		Assert.assertNull(recovered);
	}

//	/**
//	 * Test method for
//	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}.
//	 */
//	@Test
//	public void testEncryptOutputStreamSecretKey() {
//		fail("Not yet implemented");
//	}
//
//	/**
//	 * Test method for
//	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.io.InputStream, javax.crypto.SecretKey)}.
//	 */
//	@Test
//	public void testDecryptInputStreamSecretKey() {
//		fail("Not yet implemented");
//	}

}
