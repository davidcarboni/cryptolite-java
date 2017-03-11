package com.github.davidcarboni.cryptolite;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Test for {@link KeyExchange}.
 *
 * @author David Carboni
 */
public class KeyExchangeTest {

    KeyExchange keyExchange = new KeyExchange();
    static KeyPair keyPair;

    /**
     * Generates a {@link KeyPair} and instantiates a {@link DigitalSignature}.
     */
    @BeforeClass
    public static void setUpBeforeClass() {
        keyPair = Keys.newKeyPair();
    }

    /**
     * Instantiates the {@link KeyExchange} instance.
     */
    @Before
    public void setUp() {
        keyExchange = new KeyExchange();
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.KeyExchange#encryptKey(javax.crypto.SecretKey, java.security.PublicKey)}
     * . This is in fact a repeat of {@link #testDecryptKey()} with slightly different semantics.
     */
    @Test
    public void testEncryptKey() {

        // Given
        SecretKey key = Keys.newSecretKey();
        PublicKey destinationPublicKey = keyPair.getPublic();

        // When
        String encryptedKey = keyExchange.encryptKey(key, destinationPublicKey);

        // Then
        SecretKey decryptedKey = keyExchange.decryptKey(encryptedKey, keyPair.getPrivate());
        assertTrue(Arrays.equals(key.getEncoded(), decryptedKey.getEncoded()));
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.KeyExchange#decryptKey(java.lang.String, java.security.PrivateKey)}
     * . This is in fact a repeat of {@link #testEncryptKey()} with slightly different semantics.
     */
    @Test
    public void testDecryptKey() {

        // Given
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
     * {@link com.github.davidcarboni.cryptolite.KeyExchange#encryptKey(javax.crypto.SecretKey, java.security.PublicKey)}
     * . This is in fact a repeat of {@link #testDecryptKey()} with slightly different semantics.
     */
    @Test
    public void testEncryptKeyNull() {

        // Given
        SecretKey key = null;
        PublicKey publicKey = keyPair.getPublic();

        // When
        String encryptedKey = keyExchange.encryptKey(key, publicKey);

        // Then
        assertNull(encryptedKey);
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.KeyExchange#decryptKey(java.lang.String, java.security.PrivateKey)}
     * . This is in fact a repeat of {@link #testEncryptKey()} with slightly different semantics.
     */
    @Test
    public void testDecryptKeyNull() {

        // Given
        String encryptedKey = null;
        PrivateKey privateKey = keyPair.getPrivate();

        // When
        SecretKey decryptedKey = keyExchange.decryptKey(encryptedKey, privateKey);

        // Then
        assertNull(decryptedKey);
    }

}
