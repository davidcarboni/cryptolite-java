package com.github.davidcarboni.cryptolite;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * Test for {@link Random}.
 *
 * @author David Carboni
 */
public class RandomTest {

    /**
     * Clears the cached instance.
     *
     * @throws NoSuchFieldException   {@link NoSuchFieldException}.
     * @throws IllegalAccessException {@link IllegalAccessException}.
     */
    @Before
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        Field field = Random.class.getDeclaredField("secureRandom");
        field.setAccessible(true);
        field.set(Random.class, null);
    }

    /**
     * Test method for {@link com.github.davidcarboni.cryptolite.Random#getInstance()}. Checks that
     * {@link Random#getInstance()} returns the same instance on every call, avoiding initialising a
     * new instance every time.
     */
    @Test
    public void testGetInstance() {

        // Given
        SecureRandom firstCall;
        SecureRandom secondCall;

        // When
        firstCall = Random.getInstance();
        secondCall = Random.getInstance();

        // Then
        assertSame(firstCall, secondCall);
    }

    /**
     * Checks that generating a random byte array returns the expected number of bytes.
     */
    @Test
    public void testByteArray() {

        // Given
        int length = 20;

        // When
        byte[] data = Random.byteArray(length);

        // Then
        assertEquals(length, data.length);
    }

    /**
     * Checks that the number of bits in the returned ID is the same as specified by {@link Random#TOKEN_BITS}.
     */
    @Test
    public void testTokenLength() {

        // When
        // We generate a token
        String token = Random.token();

        // Then
        // It should be of the expected length
        byte[] tokenBytes = ByteArray.fromHexString(token);
        assertEquals(Random.TOKEN_BITS, tokenBytes.length * 8);
    }

    /**
     * Checks that the number of bytes in a returned salt value matches the length specified in
     * {@link Random#SALT_BYTES}.
     */
    @Test
    public void testSaltLength() {

        // When
        // We generate a salt
        String salt = Random.salt();

        // Then
        // It should be of the expected length
        byte[] salt_bytes = ByteArray.fromBase64String(salt);
        assertEquals(Random.SALT_BYTES, salt_bytes.length);
    }

    /**
     * Verifies that a random input stream provides the expected amout of input.
     *
     * @throws IOException .
     */
    @Test
    public void testInputStream() throws IOException {

        // Given
        int length = 1025;
        InputStream inputStream = Random.inputStream(length);

        // When
        int count = 0;
        while (inputStream.read() != -1) {
            count++;
        }

        // Then
        assertEquals(length, count);
    }

    /**
     * Checks the number of characters in the returned password matches the specified length of the password.
     */
    @Test
    public void testPasswordLength() {

        // Given
        String password;
        final int maxLength = 100;

        for (int length = 1; length < maxLength; length++) {

            // When
            password = Random.password(length);

            // Then
            assertEquals(length, password.length());
        }
    }

    /**
     * Test the general randomness of token generation.
     * <p>
     * If this test fails, consider yourself astoundingly lucky.. or check the code is really producing random numbers.
     */
    @Test
    public void testRandomnessOfTokens() {

        final int iterations = 1000;
        for (int i = 0; i < iterations; i++) {

            // When
            String id1 = Random.token();
            String id2 = Random.token();

            // Then
            assertNotEquals(id1, id2);
        }
    }

    /**
     * Test the general randomness of salt generation.
     * <p>
     * If this test fails, consider yourself astoundingly lucky.. or check the code is really producing random numbers.
     */
    @Test
    public void testRandomnessOfSalt() {

        final int iterations = 1000;
        for (int i = 0; i < iterations; i++) {

            // When
            String salt1 = Random.salt();
            String salt2 = Random.salt();

            // Then
            assertNotEquals(salt1, salt2);
        }
    }

    /**
     * Test the general randomness of password generation.
     * <p>
     * If this test fails, consider yourself astoundingly lucky.. or check the code is really producing random numbers.
     */
    @Test
    public void testRandomnessOfPasswords() {

        final int iterations = 1000;
        final int passwordSize = 8;
        for (int i = 0; i < iterations; i++) {

            // When
            String password1 = Random.password(passwordSize);
            String password2 = Random.password(passwordSize);

            // Then
            assertNotEquals(password1, password2);
        }
    }

}
