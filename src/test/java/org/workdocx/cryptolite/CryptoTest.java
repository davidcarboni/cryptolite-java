/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import static org.junit.Assert.assertEquals;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.SecretKey;

import junit.framework.Assert;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

/**
 * 
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

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}.
	 * 
	 * @throws IOException .
	 */
	@Test
	public void testEncryptOutputStreamSecretKey() throws IOException {

		// Given 
		String content = Random.generateId();
		SecretKey key = Keys.newSecretKey();
		File file = File.createTempFile(this.getClass().getSimpleName(), "testEncryptOutputStreamSecretKey");
		OutputStream destination = new BufferedOutputStream(new FileOutputStream(file));

		// When
		OutputStream outputStream = crypto.encrypt(destination, key);
		IOUtils.write(content, outputStream);
		IOUtils.closeQuietly(outputStream);

		// Then
		InputStream source = new BufferedInputStream(new FileInputStream(file));
		InputStream inputStream = crypto.decrypt(source, key);
		String recovered = IOUtils.readLines(inputStream).get(0);
		assertEquals(content, recovered);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.io.InputStream, javax.crypto.SecretKey)}.
	 * This test is in fact the same as {@link #testEncryptOutputStreamSecretKey()}.
	 * 
	 * @throws IOException .
	 */
	@Test
	public void testDecryptInputStreamSecretKey() throws IOException {

		// Given 
		String content = Random.generateId();
		SecretKey key = Keys.newSecretKey();
		File file = File.createTempFile(this.getClass().getSimpleName(), "testDecryptInputStreamSecretKey");
		OutputStream destination = new BufferedOutputStream(new FileOutputStream(file));
		OutputStream outputStream = crypto.encrypt(destination, key);
		IOUtils.write(content, outputStream);
		IOUtils.closeQuietly(outputStream);

		// When
		InputStream source = new BufferedInputStream(new FileInputStream(file));
		InputStream inputStream = crypto.decrypt(source, key);

		// Then
		String recovered = IOUtils.readLines(inputStream).get(0);
		assertEquals(content, recovered);
	}

}
