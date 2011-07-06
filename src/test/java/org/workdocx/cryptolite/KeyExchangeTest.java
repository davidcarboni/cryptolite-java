/**
 * 
 */
package org.workdocx.cryptolite;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.JCERSAPrivateKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import org.junit.Before;
import org.junit.Test;

/**
 * Test for {@link KeyExchange}.
 * 
 * @author David Carboni
 * 
 */
public class KeyExchangeTest {
	private KeyExchange keyExchange = new KeyExchange();

	/**
	 * Instantiates the {@link KeyExchange} instance.
	 */
	@Before
	public void setUp() {
		keyExchange = new KeyExchange();
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.KeyExchange#encryptKey(javax.crypto.SecretKey, java.security.PublicKey)}
	 * . This is in fact a repeat of {@link #testDecryptKey()} with slightly different semantics.
	 */
	@Test
	public void testEncryptKey() {

		// Given
		KeyPair keyPair = Keys.newKeyPair();
		SecretKey key = Keys.newSecretKey();
		PublicKey destinationPublicKey = keyPair.getPublic();

		// When 
		System.out.println("Key size = " + ((JCERSAPublicKey) destinationPublicKey).getModulus().bitLength());
		String encryptedKey = keyExchange.encryptKey(key, destinationPublicKey);

		// Then
		System.out.println("Key size = " + ((JCERSAPrivateKey) keyPair.getPrivate()).getModulus().bitLength());
		SecretKey decryptedKey = keyExchange.decryptKey(encryptedKey, keyPair.getPrivate());
		assertTrue(Arrays.equals(key.getEncoded(), decryptedKey.getEncoded()));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.KeyExchange#decryptKey(java.lang.String, java.security.PrivateKey)}
	 * . This is in fact a repeat of {@link #testEncryptKey()} with slightly different semantics.
	 */
	@Test
	public void testDecryptKey() {

		// Given
		KeyPair keyPair = Keys.newKeyPair();
		SecretKey key = Keys.newSecretKey();
		PublicKey destinationPublicKey = keyPair.getPublic();
		String encryptedKey = keyExchange.encryptKey(key, destinationPublicKey);

		// When 
		SecretKey decryptedKey = keyExchange.decryptKey(encryptedKey, keyPair.getPrivate());

		// Then
		assertTrue(Arrays.equals(key.getEncoded(), decryptedKey.getEncoded()));
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.KeyExchange#encryptKey(javax.crypto.SecretKey, java.security.PublicKey)}
	 * . This is in fact a repeat of {@link #testDecryptKey()} with slightly different semantics.
	 */
	@Test
	public void testEncryptKeyNull() {

		// Given
		SecretKey key = null;
		PublicKey publicKey = Keys.newKeyPair().getPublic();

		// When 
		String encryptedKey = keyExchange.encryptKey(key, publicKey);

		// Then
		assertNull(encryptedKey);
	}

	/**
	 * Test method for
	 * {@link org.workdocx.cryptolite.KeyExchange#decryptKey(java.lang.String, java.security.PrivateKey)}
	 * . This is in fact a repeat of {@link #testEncryptKey()} with slightly different semantics.
	 */
	@Test
	public void testDecryptKeyNull() {

		// Given
		String encryptedKey = null;
		PrivateKey privateKey = Keys.newKeyPair().getPrivate();

		// When 
		SecretKey decryptedKey = keyExchange.decryptKey(encryptedKey, privateKey);

		// Then
		assertNull(decryptedKey);
	}

}
