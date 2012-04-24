/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * Test for {@link DigitalSignature}.
 * 
 * @author David Carboni
 * 
 */
public class DigitalSignatureTest {

	private DigitalSignature digitalSignature;
	private static KeyPair keyPair;

	/**
	 * Generates a {@link KeyPair} and instantiates a {@link DigitalSignature}.
	 */
	@BeforeClass
	public static void setUpBeforeClass() {
		keyPair = Keys.newKeyPair();
	}

	/**
	 * Generates a {@link KeyPair} and instantiates a {@link DigitalSignature}.
	 */
	@Before
	public void setUp() {
		digitalSignature = new DigitalSignature();
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.lang.String, java.security.PrivateKey)}
	 * .
	 */
	@Test
	public void shouldReturnNullForNullContentString() {

		// Given
		String content = null;
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		String signature = digitalSignature.sign(content, privateKey);

		// Then
		assertNull(signature);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.lang.String, java.security.PrivateKey)}
	 * .
	 */
	@Test
	public void testSignStringPrivateKey() {

		// Given
		String content = Random.generateId();
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		String signature = digitalSignature.sign(content, privateKey);

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		assertTrue(digitalSignature.verify(content, keyPair.getPublic(), signature));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.lang.String, java.security.PrivateKey)}
	 * .
	 */
	@Test
	public void testSignStringPrivateKeyFail() {

		// Given
		String content = Random.generateId();
		String changedContent = content + "X";
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		String signature = digitalSignature.sign(content, privateKey);

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		assertFalse(digitalSignature.verify(changedContent, keyPair.getPublic(), signature));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.io.InputStream, java.security.PrivateKey)}
	 * .
	 */
	@Test
	public void shouldReturnNullForNullContentStream() {

		// Given
		InputStream content = null;
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		String signature = digitalSignature.sign(content, privateKey);

		// Then
		assertNull(signature);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.io.InputStream, java.security.PrivateKey)}
	 * .
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test
	public void testSignInputStreamPrivateKey() throws IOException {

		// Given
		File file = FileUtils.newFile();
		InputStream content = new FileInputStream(file);
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		String signature = digitalSignature.sign(content, privateKey);
		content.close();

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		content = new FileInputStream(file);
		assertTrue(digitalSignature.verify(content, keyPair.getPublic(), signature));
		content.close();
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.io.InputStream, java.security.PrivateKey)}
	 * .
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test(expected = RuntimeException.class)
	public void testSignInputStreamPrivateKeyException() throws IOException {

		// Given
		File file = FileUtils.newFile();
		InputStream content = new FileInputStream(file);
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		content.close();
		digitalSignature.sign(content, privateKey);

		// Then
		// We should have the expected exception.
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#sign(java.io.InputStream, java.security.PrivateKey)}
	 * .
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test
	public void testSignInputStreamPrivateKeyFail() throws IOException {

		// Given
		File file = FileUtils.newFile();
		File fileChanged = FileUtils.newFile();
		InputStream content = new FileInputStream(file);
		PrivateKey privateKey = keyPair.getPrivate();

		// When
		String signature = digitalSignature.sign(content, privateKey);
		content.close();

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		content = new FileInputStream(fileChanged);
		assertFalse(digitalSignature.verify(content, keyPair.getPublic(), signature));
		content.close();
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#verify(java.lang.String, java.security.PublicKey, java.lang.String)}
	 * .
	 */
	@Test
	public void testVerifyStringPublicKeyString() {

		// Given
		String content = Random.generateId();
		PublicKey publicKey = keyPair.getPublic();
		String signature = digitalSignature.sign(content, keyPair.getPrivate());

		// When
		boolean result = digitalSignature.verify(content, publicKey, signature);

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		assertTrue(result);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#verify(java.lang.String, java.security.PublicKey, java.lang.String)}
	 * .
	 */
	@Test
	public void testVerifyStringPublicKeyStringFail() {

		// Given
		String content = Random.generateId();
		String changedContent = content + "X";
		PublicKey publicKey = keyPair.getPublic();
		String signature = digitalSignature.sign(content, keyPair.getPrivate());

		// When
		boolean result = digitalSignature.verify(changedContent, publicKey, signature);

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		assertFalse(result);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#verify(java.io.InputStream, java.security.PublicKey, java.lang.String)}
	 * .
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test
	public void testVerifyInputStreamPublicKeyString() throws IOException {

		// Given
		File file = FileUtils.newFile();
		InputStream content = new FileInputStream(file);
		PrivateKey privateKey = keyPair.getPrivate();
		String signature = digitalSignature.sign(content, privateKey);
		content.close();

		// When
		content = new FileInputStream(file);
		boolean result = digitalSignature.verify(content, keyPair.getPublic(), signature);
		content.close();

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		assertTrue(result);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#verify(java.io.InputStream, java.security.PublicKey, java.lang.String)}
	 * .
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test(expected = RuntimeException.class)
	public void testVerifyInputStreamPublicKeyStringException() throws IOException {

		// Given
		File file = FileUtils.newFile();
		InputStream content = new FileInputStream(file);
		PrivateKey privateKey = keyPair.getPrivate();
		String signature = digitalSignature.sign(content, privateKey);
		content.close();

		// When
		content = new FileInputStream(file);
		content.close();
		digitalSignature.verify(content, keyPair.getPublic(), signature);

		// Then
		// We should have the expected exception.
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.DigitalSignature#verify(java.io.InputStream, java.security.PublicKey, java.lang.String)}
	 * .
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test
	public void testVerifyInputStreamPublicKeyStringFail() throws IOException {

		// Given
		File file = FileUtils.newFile();
		File fileChanged = FileUtils.newFile();
		InputStream content = new FileInputStream(file);
		PrivateKey privateKey = keyPair.getPrivate();
		String signature = digitalSignature.sign(content, privateKey);
		content.close();

		// When
		content = new FileInputStream(fileChanged);
		boolean result = digitalSignature.verify(content, keyPair.getPublic(), signature);
		content.close();

		// Then
		System.out.println("Signature: " + signature + " (" + signature.length() + ")");
		assertFalse(result);
	}

}
