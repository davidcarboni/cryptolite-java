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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;

/**
 * @author David Carboni
 * 
 */
public class CryptoNewTest {

	private static final CryptoNew cryptoNew = new CryptoNew();
	private static final SecretKey key = Keys.newSecretKey();

	/**
	 * Takes a peek inside the {@link CryptoNew} instance to verify that the {@link Cipher} is
	 * indeed using the algorithm defined by {@link CryptoNew#CIPHER_NAME}.
	 * 
	 * @throws NoSuchFieldException
	 *             {@link NoSuchFieldException}
	 * @throws SecurityException
	 *             {@link SecurityException}
	 * @throws IllegalAccessException
	 *             {@link IllegalAccessException}
	 * @throws IllegalArgumentException
	 *             {@link IllegalArgumentException}
	 */
	@Test
	public void testCryptoNew() throws SecurityException, NoSuchFieldException, IllegalArgumentException,
			IllegalAccessException {

		// Given
		Field cipherField = CryptoNew.class.getDeclaredField("cipher");
		cipherField.setAccessible(true);
		Cipher cipher = (Cipher) cipherField.get(cryptoNew);

		// Then
		assertEquals(CryptoNew.CIPHER_NAME, cipher.getAlgorithm());
	}

	/**
	 * Verifies that null is returned for null encryption input.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#encrypt(java.lang.String, javax.crypto.SecretKey)}.
	 * 
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldNotEncryptNullString() throws InvalidKeyException {

		// Given 
		String plaintext = null;

		// When
		String ciphertext = cryptoNew.encrypt(plaintext, key);

		// Then 
		assertNull(ciphertext);
	}

	/**
	 * Verifies that an empty String gets encrypted.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#encrypt(java.lang.String, javax.crypto.SecretKey)}.
	 * 
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldEncryptEmptyString() throws InvalidKeyException {

		// Given 
		String plaintext = "";

		// When
		String ciphertext = cryptoNew.encrypt(plaintext, key);

		// Then 
		assertNotNull(ciphertext);
		assertFalse(StringUtils.isEmpty(ciphertext));
		assertEquals(plaintext, cryptoNew.decrypt(ciphertext, key));
	}

	/**
	 * Verifies that the same String gets encrypted differently every time.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#encrypt(java.lang.String, javax.crypto.SecretKey)}.
	 * 
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldEncryptSameStringDifferently() throws InvalidKeyException {

		// Given 
		String plaintext = "The quick brown fox jumped over the lazy dog.";
		// Ignore any newlines:
		String ciphertext1 = cryptoNew.encrypt(plaintext, key).replace("\n", "").replace("\r", "");
		int length = ciphertext1.length();
		boolean[] different = new boolean[length];
		final int maxAttempts = 100;
		int attempt = 0;

		// When
		// Encrypt the same string over and over  until
		// we have seen a different character at every position:
		while (ArrayUtils.contains(different, false) && attempt++ < maxAttempts) {

			String ciphertext2 = cryptoNew.encrypt(plaintext, key).replace("\n", "").replace("\r", "");
			for (int i = 0; i < length; i++) {
				// Compare each character, but ignore base-64 padding:
				different[i] |= ciphertext1.charAt(i) != ciphertext2.charAt(i) || ciphertext1.charAt(i) == '=';
			}
		}

		// Then 
		assertFalse(ArrayUtils.contains(different, false));
	}

	/**
	 * Verifies that null is returned for null decryption input.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#decrypt(java.lang.String, javax.crypto.SecretKey)}.
	 * 
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldNotDecryptNullString() throws InvalidKeyException {

		// Given 
		String ciphertext = null;

		// When
		String plaintext = cryptoNew.decrypt(ciphertext, key);

		// Then 
		assertNull(plaintext);
	}

	/**
	 * Verifies that an empty string is returned for empty decryption input.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#decrypt(java.lang.String, javax.crypto.SecretKey)}.
	 * 
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldNotDecryptEmptyString() throws InvalidKeyException {

		// Given 
		String ciphertext = "";

		// When
		String plaintext = cryptoNew.decrypt(ciphertext, key);

		// Then 
		assertEquals(ciphertext, plaintext);
	}

	/**
	 * Verifies that decryption is successful and consistent, even for different ciphertext Strings.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#decrypt(java.lang.String, javax.crypto.SecretKey)}.
	 * 
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldDecryptDifferentStringsToSamePlaintext() throws InvalidKeyException {

		// Given 
		String input = "My love is like a red, red rose.";
		String ciphertext1 = cryptoNew.encrypt(input, key);
		String ciphertext2;
		do {
			// Ensure we have a different String:
			ciphertext2 = cryptoNew.encrypt(input, key);
		} while (ciphertext1.equals(ciphertext2));

		// When
		String plaintext1 = cryptoNew.decrypt(ciphertext1, key);
		String plaintext2 = cryptoNew.decrypt(ciphertext2, key);

		// Then 
		assertEquals(input, plaintext1);
		assertEquals(plaintext1, plaintext2);
	}

	/**
	 * Verifies that attempting to encrypt a null output stream just returns null.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
	 * .
	 * 
	 * @throws IOException
	 *             {@link IOException}
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldNotEncryptNullOutputStream() throws InvalidKeyException, IOException {

		// Given 
		OutputStream destination = null;

		// When
		OutputStream encryptor = cryptoNew.encrypt(destination, key);

		// Then 
		assertNull(encryptor);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
	 * .
	 * 
	 * @throws IOException
	 *             {@link IOException}
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldEncryptSameDataDifferently() throws InvalidKeyException, IOException {

		// Given 
		byte[] data = ("Three french hens, two turtle doves " + "and a partridge in a pear tree.").getBytes("UTF8");
		ByteArrayOutputStream destination = new ByteArrayOutputStream();
		int size = IOUtils.copy(new ByteArrayInputStream(data), cryptoNew.encrypt(destination, key));
		byte[] ciphertext1 = destination.toByteArray();
		boolean[] different = new boolean[size];
		final int maxAttempts = 100;
		int attempt = 0;

		// When
		// Encrypt the same data over and over until
		// we have seen a different byte at every position:
		while (ArrayUtils.contains(different, false) && attempt++ < maxAttempts) {

			destination = new ByteArrayOutputStream();
			IOUtils.copy(new ByteArrayInputStream(data), cryptoNew.encrypt(destination, key));
			byte[] ciphertext2 = destination.toByteArray();
			for (int i = 0; i < size; i++) {
				// Compare each byte:
				different[i] |= ciphertext1[i] != ciphertext2[i];
			}
		}

		// Then
		assertFalse(ArrayUtils.contains(different, false));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.CryptoNew#decrypt(java.io.InputStream, javax.crypto.SecretKey)}
	 * .
	 * 
	 * @throws IOException
	 * @throws InvalidKeyException
	 */
	@Test
	public void testDecryptInputStreamSecretKey() throws InvalidKeyException, IOException {

		// Given 
		byte[] input = ("It's really important, you know, to take care of other peoples' stuff "
				+ "if they are trusting you to look after it.").getBytes("UTF8");
		ByteArrayOutputStream destination = new ByteArrayOutputStream();
		OutputStream encryptor;
		encryptor = cryptoNew.encrypt(destination, key);
		IOUtils.copy(new ByteArrayInputStream(input), encryptor);
		encryptor.close();
		byte[] ciphertext1 = destination.toByteArray();
		byte[] ciphertext2;
		do {
			// Ensure we have a different byte array:
			destination = new ByteArrayOutputStream();
			encryptor = cryptoNew.encrypt(destination, key);
			IOUtils.copy(new ByteArrayInputStream(input), encryptor);
			encryptor.close();
			ciphertext2 = destination.toByteArray();
		} while (Arrays.equals(ciphertext1, ciphertext2));

		// When
		destination = new ByteArrayOutputStream();
		IOUtils.copy(cryptoNew.decrypt(new ByteArrayInputStream(ciphertext1), key), destination);
		byte[] plaintext1 = destination.toByteArray();
		destination = new ByteArrayOutputStream();
		IOUtils.copy(cryptoNew.decrypt(new ByteArrayInputStream(ciphertext2), key), destination);
		byte[] plaintext2 = destination.toByteArray();

		// Then 
		assertTrue(Arrays.equals(input, plaintext1));
		assertTrue(Arrays.equals(plaintext1, plaintext2));
	}

	public static void main(String[] args) throws InvalidKeyException {

		SecretKey key = Keys.newSecretKey();
		Crypto crypto1 = new Crypto();
		CryptoNew crypto2 = new CryptoNew();

		String input = "I think I understand now.";

		for (int n = 0; n < 5; n++) {

			System.out.println(input);

			String ciphertext1a = crypto1.encrypt(input, key).trim();
			String plaintext1a = crypto1.decrypt(ciphertext1a, key);
			System.out.println("Crypto1: " + ciphertext1a + " -> " + plaintext1a);

			String ciphertext1b = crypto1.encrypt(input, key).trim();
			String plaintext1b = crypto1.decrypt(ciphertext1b, key);
			System.out.println("Crypto1: " + ciphertext1b + " -> " + plaintext1b);

			String ciphertext2a = crypto2.encrypt(input, key).trim();
			String plaintext2a = crypto2.decrypt(ciphertext2a, key);
			System.out.println("CryptoNew: " + ciphertext2a + " -> " + plaintext2a);

			String ciphertext2b = crypto2.encrypt(input, key).trim();
			String plaintext2b = crypto2.decrypt(ciphertext2b, key);
			System.out.println("CryptoNew: " + ciphertext2b + " -> " + plaintext2b);

			String ciphertext1am = migrateCiphertext(ciphertext1a);
			String ciphertext1bm = migrateCiphertext(ciphertext1b);
			String plaintext1am = crypto2.decrypt(ciphertext1am, key);
			plaintext1am = migratePlaintext(plaintext1am);
			System.out.println("CryptoM: " + ciphertext1am + " -> " + plaintext1am);
			String plaintext1bm = crypto2.decrypt(ciphertext1bm, key);
			plaintext1bm = migratePlaintext(plaintext1bm);
			System.out.println("CryptoM: " + ciphertext1bm + " -> " + plaintext1bm);
			System.out.println();
		}
	}

	private static String migrateCiphertext(String ciphertext) {

		CryptoNew crypto = new CryptoNew();
//		byte[] iv = crypto.generateInitialisationVector(crypto.cipher);
		byte[] iv = new byte[crypto.generateInitialisationVector().length];
		byte[] migrate = Codec.fromBase64String(ciphertext);
		migrate = ArrayUtils.addAll(iv, migrate);
//		for (int i = 0; i < iv.length; i++) {
//			migrate[i] = 0;
//		}
		return Codec.toBase64String(migrate).trim();
	}

	private static String migratePlaintext(String plaintext) {
		byte[] bytes = Codec.toByteArray(plaintext);
		CryptoNew crypto = new CryptoNew();
		bytes = ArrayUtils.subarray(bytes, crypto.generateInitialisationVector().length, bytes.length);
		return Codec.fromByteArray(bytes);
	}

}
