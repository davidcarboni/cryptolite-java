package com.github.davidcarboni.cryptolite;

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test for {@link KeyWrapper}.
 *
 * @author David Carboni
 */
public class KeyWrapperTest {

    static KeyPair keyPair;

    /**
     * Generates a {@link KeyPair} and instantiates a {@link DigitalSignature}.
     */
    @BeforeClass
    public static void setUpBeforeClass() {
        // Use standard keys to make sure tests run in any environment:
        Keys.useStandardKeys();
        keyPair = Keys.newKeyPair();
    }

    /**
     * Test for {@link KeyWrapper#KeyWrapper(String, String)}.
     * <p>
     * Checks that two instances initialised with the same password and salt
     * both generate the same key.
     */
    @Test
    public void testKeyWrapperStringString() {

        // Given
        String password = "testKeyWrapperStringString";
        String salt = Generate.salt();

        // When
        KeyWrapper keyWrapper = new KeyWrapper(password, salt);
        KeyWrapper keyWrapperPass = new KeyWrapper(password, salt);
        KeyWrapper keyWrapperFail = new KeyWrapper(password + "x", salt);

        // Then
        // The following should work:
        SecretKey key = Keys.newSecretKey();
        String wrappedKey = keyWrapper.wrapSecretKey(key);
        try {
            keyWrapperPass.unwrapSecretKey(wrappedKey);
        } catch (RuntimeException e) {
            fail("Unable to unwrap key");
        }
        // The following should not work -
        // this validates that the check above
        // is actually checking something:
        try {
            keyWrapperFail.unwrapSecretKey(wrappedKey);
            fail("Please check the assumptions for this test");
        } catch (RuntimeException e) {
            // Expected. If we don't get this
            // then something has changed and
            // this test should flag that it
            // needs updating.
        }
    }

    /**
     * Test for {@link KeyWrapper#wrapSecretKey(SecretKey)}.
     */
    @Test
    public void testWrapSecretKey() {

        // Given
        String password = "testWrapSecretKey";
        String salt = Generate.salt();
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
        String salt = Generate.salt();
        PrivateKey key = keyPair.getPrivate();
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
        PublicKey key = keyPair.getPublic();

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
        String salt = Generate.salt();
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
        String salt = Generate.salt();
        PrivateKey key = keyPair.getPrivate();
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
        PublicKey key = keyPair.getPublic();
        String wrappedKey = KeyWrapper.encodePublicKey(key);

        // When
        PublicKey recovered = KeyWrapper.decodePublicKey(wrappedKey);

        // Then
        assertTrue(Arrays.equals(key.getEncoded(), recovered.getEncoded()));
    }

}
