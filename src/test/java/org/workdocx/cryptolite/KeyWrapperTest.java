/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.Test;

/**
 * 
 * Test for {@link KeyWrapper}.
 * 
 * @author David Carboni
 * 
 */
public class KeyWrapperTest {

	/**
	 * Test for {@link KeyWrapper#KeyWrapper(String, String)}.
	 * <p>
	 * Checks that two instances initialised with the same password and salt both generate the same
	 * key.
	 */
	@Test
	public void testKeyWrapperStringString() {

		// Given 
		String password = "testKeyWrapperStringString";
		String salt = Random.generateSalt();

		// When
		KeyWrapper keyWrapper1 = new KeyWrapper(password, salt);
		KeyWrapper keyWrapper2 = new KeyWrapper(password, salt);

		// Then
		assertEquals(keyWrapper1.getWrapKey(), keyWrapper2.getWrapKey());
	}

	/**
	 * Test for {@link KeyWrapper#KeyWrapper(String)}.
	 * <p>
	 * Checks that an instance initialised with a key, rather than a password and salt contains the
	 * same key.
	 */
	@Test
	public void testKeyWrapperString() {

		// Given 
		String password = "testKeyWrapperString";
		String salt = Random.generateSalt();
		KeyWrapper keyWrapperPasswordSalt = new KeyWrapper(password, salt);

		// When
		KeyWrapper keyWrapperKey = new KeyWrapper(keyWrapperPasswordSalt.getWrapKey());

		// Then
		assertEquals(keyWrapperPasswordSalt.getWrapKey(), keyWrapperKey.getWrapKey());
	}

	/**
	 * Test for {@link KeyWrapper#wrapSecretKey(SecretKey)}.
	 */
	@Test
	public void testWrapSecretKey() {

		// Given 
		String password = "testWrapSecretKey";
		String salt = Random.generateSalt();
		SecretKey key = Keys.newSecretKey();
		KeyWrapper keyWrapper = new KeyWrapper(password, salt);

		// When
		String wrappedKey = keyWrapper.wrapSecretKey(key);

		// Then
		SecretKey recovered = keyWrapper.unwrapSecretKey(wrappedKey);
		assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
	}

	/**
	 * Test for {@link KeyWrapper#wrapPrivateKey(PrivateKey)}.
	 */
	@Test
	public void testWrapPrivateKey() {

		// Given 
		String password = "testWrapPrivateKey";
		String salt = Random.generateSalt();
		PrivateKey key = Keys.newKeyPair().getPrivate();
		KeyWrapper keyWrapper = new KeyWrapper(password, salt);

		// When
		String wrappedKey = keyWrapper.wrapPrivateKey(key);

		// Then
		PrivateKey recovered = keyWrapper.unwrapPrivateKey(wrappedKey);
		assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
	}

	/**
	 * Test for {@link KeyWrapper#encodePublicKey(PublicKey)}.
	 */
	@Test
	public void testEncodePublicKey() {

		// Given 
		PublicKey key = Keys.newKeyPair().getPublic();

		// When
		String wrappedKey = KeyWrapper.encodePublicKey(key);

		// Then
		PublicKey recovered = KeyWrapper.decodePublicKey(wrappedKey);
		assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
	}

	/**
	 * Test for {@link KeyWrapper#unwrapSecretKey(String)}.
	 */
	@Test
	public void testUnwrapSecretKey() {

		// Given 
		String password = "testUnwrapSecretKey";
		String salt = Random.generateSalt();
		SecretKey key = Keys.newSecretKey();
		KeyWrapper keyWrapper = new KeyWrapper(password, salt);
		String wrappedKey = keyWrapper.wrapSecretKey(key);

		// When
		SecretKey recovered = keyWrapper.unwrapSecretKey(wrappedKey);

		// Then
		assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
	}

	/**
	 * Test for {@link KeyWrapper#unwrapPrivateKey(String)}.
	 */
	@Test
	public void testUnwrapPrivateKey() {

		// Given 
		String password = "testWrapPrivateKey";
		String salt = Random.generateSalt();
		PrivateKey key = Keys.newKeyPair().getPrivate();
		KeyWrapper keyWrapper = new KeyWrapper(password, salt);
		String wrappedKey = keyWrapper.wrapPrivateKey(key);

		// When
		PrivateKey recovered = keyWrapper.unwrapPrivateKey(wrappedKey);

		// Then
		assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
	}

	/**
	 * Test for {@link KeyWrapper#decodePublicKey(String)}.
	 */
	@Test
	public void testDecodePublicKey() {

		// Given 
		PublicKey key = Keys.newKeyPair().getPublic();
		String wrappedKey = KeyWrapper.encodePublicKey(key);

		// When
		PublicKey recovered = KeyWrapper.decodePublicKey(wrappedKey);

		// Then
		assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
	}

	/**
	 * Test for {@link KeyWrapper#getWrapKey()} and {@link KeyWrapper#setWrapKey(String)}.
	 */
	@Test
	public void testWrapKey() {

		// Given 
		KeyWrapper keyWrapper1 = new KeyWrapper("password", Random.generateSalt());
		KeyWrapper keyWrapper2 = new KeyWrapper("something else", Random.generateSalt());

		// When
		String wrapKey = keyWrapper1.getWrapKey();
		keyWrapper2.setWrapKey(wrapKey);

		// Then
		assertEquals(wrapKey, keyWrapper2.getWrapKey());
	}

}
