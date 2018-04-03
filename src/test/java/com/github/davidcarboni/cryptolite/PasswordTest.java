package com.github.davidcarboni.cryptolite;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * Test for {@link Password}.
 *
 * @author David Carboni
 */
public class PasswordTest {

    static SecureRandom secureRandom;

    @BeforeClass
    public static void setup() throws NoSuchAlgorithmException {
        secureRandom = SecureRandom.getInstance(Generate.ALGORITHM);
    }

    /**
     * Verifies that
     * {@link com.github.davidcarboni.cryptolite.Password#hash(java.lang.String)}
     * at least returns something other than the String passed in.
     */
    @Test
    public void shouldHash() {
        // Given
        String password = "testHash";

        // When
        String hash = Password.hash(password);

        // Then
        // Simplistic check to ensure the password hasn't just been returned
        // unaltered
        assertFalse(hash.equals(password));
    }

    /**
     * Verifies that
     * {@link com.github.davidcarboni.cryptolite.Password#hash(java.lang.String)}
     * hashes the same password to a different value on subsequent invocations -
     * i.e. that the hash is salted.
     */
    @Test
    public void shouldHashDifferentlyEachTime() {

        // Given
        String password = "testHashDifferently";

        // When
        String hash1 = Password.hash(password);
        String hash2 = Password.hash(password);

        // Then
        assertFalse(hash1.equals(hash2));
    }

    /**
     * Checks that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * can successfully verify a password against its hash.
     */
    @Test
    public void shouldVerifyCorrectPassword() {

        // Given
        String password = "testVerify";
        String hash = Password.hash(password);

        // When
        boolean result = Password.verify(password, hash);

        // Then
        assertTrue(result);
    }

    /**
     * Checks that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * can successfully verify a blank password against its hash.
     */
    @Test
    public void shouldVerifyBlankPassword() {

        // Given
        String password = "";
        String hash = Password.hash(password);

        // When
        boolean result = Password.verify(password, hash);

        // Then
        assertTrue(result);
    }

    /**
     * Ensures that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * returns false for an incorrect password.
     */
    @Test
    public void shouldntVerifyIncorrectPassword() {

        // Given
        String password = "password";
        String incorrect = "something else";
        // Note we add
        String hash = Password.hash(password);

        // When
        boolean result = Password.verify(incorrect, hash);

        // Then
        assertFalse(result);
    }

    /**
     * Verifies that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * returns a polite refusal, rather than throwing an exception, if the hash
     * value is too short (ie less that the size of the salt).
     */
    @Test
    public void shouldntThrowExceptionIfHashTooShort() {

        // Given
        String password = "password";
        byte[] hashBytes = new byte[Generate.SALT_BYTES - 1];
        secureRandom.nextBytes(hashBytes);
        String hash = ByteArray.toBase64(hashBytes);

        // When
        boolean result = Password.verify(password, hash);

        // Then
        assertFalse(result);
    }

    /**
     * Checks that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * gracefully returns false, rather than throwing an exception if the hash
     * only contains enough bytes for the salt value (i.e. zero bytes for the
     * password part of the hash).
     */
    @Test
    public void shouldntThrowExceptionIfHashHasNoPassword() {

        // Given
        String password = "password";
        String hash = Generate.salt();

        // When
        boolean result = Password.verify(password, hash);

        // Then
        assertFalse(result);
    }

    /**
     * Verifies that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * returns a polite refusal, rather than throwing an exception, if the
     * password value is null.
     */
    @Test
    public void shouldntThrowExceptionIfVerifyPasswordNull() {

        // Given
        String password = null;
        String hash = Password.hash("password");

        // When
        boolean result = Password.verify(password, hash);

        // Then
        assertFalse(result);
    }

    /**
     * Verifies that
     * {@link com.github.davidcarboni.cryptolite.Password#hash(String)} returns
     * null if the password value given is null.
     */
    @Test
    public void shouldReturnNullForNullPassword() {

        // Given
        String password = null;

        // When
        String hash = Password.hash(password);

        // Then
        assertNull(hash);
    }

    /**
     * Verifies that
     * {@link com.github.davidcarboni.cryptolite.Password#verify(java.lang.String, java.lang.String)}
     * returns a polite refusal, rather than throwing an exception, if the hash
     * value is null.
     */
    @Test
    public void shouldntThrowExceptionIfVerifyHashNull() {

        // Given
        String password = "password";
        String hash = null;

        // When
        boolean result = Password.verify(password, hash);

        // Then
        assertFalse(result);
    }

}
