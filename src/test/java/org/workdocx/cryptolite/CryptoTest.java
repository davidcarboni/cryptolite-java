/**
 * Copyright (C) 2011 WorkDocx Ltd.
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
 * 
 * Test for {@link Crypto}.
 * 
 * @author David Carboni
 * 
 */
public class CryptoTest {

	private static final Crypto cryptoNew = new Crypto();
	private static final SecretKey key = Keys.newSecretKey();

	/**
	 * Takes a peek inside the {@link Crypto} instance to verify that the {@link Cipher} is indeed
	 * using the algorithm defined by {@link Crypto#CIPHER_NAME}.
	 * 
	 * @throws NoSuchFieldException
	 *             {@link NoSuchFieldException}
	 * @throws IllegalAccessException
	 *             {@link IllegalAccessException}
	 */
	@Test
	public void testCryptoNew() throws NoSuchFieldException, IllegalAccessException {

		// Given
		Field cipherField = Crypto.class.getDeclaredField("cipher");
		cipherField.setAccessible(true);
		Cipher cipher = (Cipher) cipherField.get(cryptoNew);

		// Then
		assertEquals(Crypto.CIPHER_NAME, cipher.getAlgorithm());
	}

	/**
	 * Verifies that null is returned for null encryption input.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
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
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
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
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
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
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
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
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
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
	 * Verifies that decryption is successful and consistent, even for different ciphertext Strings
	 * - ie if you encrypt something twice, the encrypted data should be different each time, but
	 * should decrypt back to the same thing.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
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
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
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
	 * {@link org.workdocx.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
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
	 * Verifies that decryption of differing ciphertext streams result in the same plaintext - ie if
	 * you encrypt something twice, the encrypted data should be different each time, but should
	 * decrypt back to the same thing.
	 * <p>
	 * Test method for
	 * {@link org.workdocx.cryptolite.Crypto#decrypt(java.io.InputStream, javax.crypto.SecretKey)} .
	 * 
	 * @throws IOException
	 *             {@link IOException}
	 * @throws InvalidKeyException
	 *             {@link InvalidKeyException}
	 */
	@Test
	public void shouldDecryptDifferentStreamsToSamePlaintext() throws InvalidKeyException, IOException {

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
}
