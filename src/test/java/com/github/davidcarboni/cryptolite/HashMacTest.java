package com.github.davidcarboni.cryptolite;

import org.apache.commons.lang.StringUtils;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Verifies the {@link HashMac} class.
 *
 * @author David Carboni
 */
public class HashMacTest {

    static final int keyLength = 8;

    /**
     * Basic check to ensure it's actually doing something.
     */
    @Test
    public void shouldDigest() {

        // Given
        String key = Generate.password(keyLength);
        String message = Generate.token();
        HashMac hashMac = new HashMac(key);

        // When
        String hmac = hashMac.digest(message);

        // Then
        assertFalse(StringUtils.isBlank(hmac));
        assertFalse(StringUtils.equals(key, hmac));
        assertFalse(StringUtils.equals(message, hmac));
    }

    /**
     * Basic check to ensure it's actually doing something.
     */
    @Test
    public void shouldVerifyWithStringKey() {

        // Given
        String key = Generate.password(keyLength);
        String message = Generate.token();
        HashMac sender = new HashMac(key);
        HashMac recipient = new HashMac(key);

        // When
        String hmac = sender.digest(message);

        // Then
        String verification = recipient.digest(message);
        assertTrue(StringUtils.equals(hmac, verification));
    }

    /**
     * Basic check to ensure it's actually doing something.
     */
    @Test
    public void shouldVerifyWithSecretKey() {

        // Given
        SecretKey key = Keys.newSecretKey();
        String message = Generate.token();
        HashMac sender = new HashMac(key);
        HashMac recipient = new HashMac(key);

        // When
        String hmac = sender.digest(message);

        // Then
        String verification = recipient.digest(message);
        assertTrue(StringUtils.equals(hmac, verification));
    }

}
