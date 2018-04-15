package com.github.davidcarboni.cryptolite;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * Test for {@link Keys}.
 *
 * @author David Carboni
 */
public class KeysTest {

    /**
     * Test method for {@link com.github.davidcarboni.cryptolite.Keys#newSecretKey()}.
     * <p>
     * This is a cursory test to check that subsequent generated keys are different. Whilst it's
     * technically possible for this test to fail, consider yourself intergalactically lucky if it
     * does - and check the code.
     */
    @Test
    public void testNewSecretKey() {

        // Given
        SecretKey key1;
        SecretKey key2;

        // When
        key1 = Keys.newSecretKey();
        key2 = Keys.newSecretKey();

        // Then
        assertNotNull(key1);
        assertNotNull(key2);
        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }

    /**
     * Test method for {@link com.github.davidcarboni.cryptolite.Keys#newKeyPair()}.
     * <p>
     * This is a cursory test to check that subsequent generated keys are different. Whilst it's
     * technically possible for this test to fail, consider yourself intergalactically lucky if it
     * does - and check the code.
     */
    @Test
    public void testNewKeyPair() {

        // Given
        KeyPair keyPair1;
        KeyPair keyPair2;

        // When
        keyPair1 = Keys.newKeyPair();
        keyPair2 = Keys.newKeyPair();

        // Then
        assertNotNull(keyPair1.getPrivate());
        assertNotNull(keyPair1.getPublic());
        assertNotNull(keyPair2.getPrivate());
        assertNotNull(keyPair2.getPublic());
        assertFalse(Arrays.equals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded()));
        assertFalse(Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()));
    }

    /**
     * Test method for {@link com.github.davidcarboni.cryptolite.Keys#generateSecretKey(String, String)}.
     * <p>
     * Tests a known password and salt value to make sure the expected key is generated.
     */
    @Test
    public void testGenerateSecretKey() {

        // Given
        // A known password/salt -> key vector
        String password = "Mary had a little Café";
        String salt = "EvwdaavC8dRvR4RPaI9Gkg==";
        String keyHex = "e73d452399476f0488b32b0bea2b8c0da35c33b122cd52c6ed35188e4117f448";

        // When
        // We generate the key
        SecretKey key = Keys.generateSecretKey(password, salt);

        // Then
        // We should get the expected key
        assertEquals(keyHex, ByteArray.toHex(key.getEncoded()));
    }


}
