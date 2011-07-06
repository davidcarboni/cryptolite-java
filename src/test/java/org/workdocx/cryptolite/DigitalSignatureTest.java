/**
 * 
 */
package org.workdocx.cryptolite;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Before;
import org.junit.Test;

/**
 * Test for {@link DigitalSignature}.
 * 
 * @author david
 * 
 */
public class DigitalSignatureTest {

	private DigitalSignature digitalSignature;
	private KeyPair keyPair;

	/**
	 */
	@Before
	public void setUp() {
		keyPair = Keys.newKeyPair();
		digitalSignature = new DigitalSignature();
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
	 * 
	 * @throws IOException
	 *             If a file IO error occurs.
	 */
	@Test
	public void testSignInputStreamPrivateKey() throws IOException {

		// Given
		File file = newFile();
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
		File file = newFile();
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
		File file = newFile();
		File fileChanged = newFile();
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
		File file = newFile();
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
		File file = newFile();
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
		File file = newFile();
		File fileChanged = newFile();
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

	// This guarantees that every file generated will be different:
	private static byte sequence;

	/**
	 * Generates a new file, containing random content. The file is a temp file, which will be
	 * deleted on exit.
	 * 
	 * @return The created file.
	 */
	private File newFile() {

		final int filesize = 256;

		// Create a temp file:
		File file;
		try {
			file = File.createTempFile(this.getClass().getSimpleName(), "testFile");
		} catch (IOException e) {
			throw new RuntimeException("Error creating temp file.", e);
		}
		file.deleteOnExit();

		// Generate some content:
		byte[] bytes = new byte[filesize];
		Random.getInstance().nextBytes(bytes);

		// Write the content to the file:
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			throw new RuntimeException("Error creating output stream.", e);
		}
		try {
			for (byte b : bytes) {
				fos.write(b);
			}
			fos.write(sequence++);
			fos.close();
		} catch (IOException e) {
			throw new RuntimeException("Error writing content to temp file.", e);
		}

		// Return the file:
		return file;
	}

}
