package com.github.davidcarboni.cryptolite;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Test for {@link Generate}.
 *
 * @author David Carboni
 */
public class GenerateTest {

    /**
     * Checks that generating a random byte array returns the expected number of bytes.
     */
    @Test
    public void testByteArray() {

        // Given
        int length = 20;

        // When
        byte[] randomBytes = Generate.byteArray(length);

        // Then
        assertEquals("Unexpected random byte lenth.", length, randomBytes.length);
    }

    /**
     * Checks that the number of bits in the returned ID is the same as specified by {@link Generate#TOKEN_BITS}.
     */
    @Test
    public void testTokenLength() {

        // When
        // We generate a token
        String token = Generate.token();

        // Then
        // It should be of the expected length
        byte[] tokenBytes = ByteArray.fromHex(token);
        assertEquals("Unexpected token bit-length", Generate.TOKEN_BITS, tokenBytes.length * 8);
    }

    /**
     * Checks that the number of bytes in a returned salt value matches the length specified in
     * {@link Generate#SALT_BYTES}.
     */
    @Test
    public void testSaltLength() {

        // When
        // We generate a salt
        String salt = Generate.salt();

        // Then
        // It should be of the expected length
        byte[] saltBytes = ByteArray.fromBase64(salt);
        assertEquals("Unexpected salt byte-length", Generate.SALT_BYTES, saltBytes.length);
    }

    /**
     * Checks the number of characters and the content of the returned password matches the expected content.
     */
    @Test
    public void testPassword() {

        // Given
        String password;
        final int maxLength = 100;

        for (int length = 1; length < maxLength; length++) {

            // When
            password = Generate.password(length);

            // Then
            assertEquals("Unexpected password length", length, password.length());
            assertTrue("Unexpected password content", password.matches("[A-Za-z0-9]+"));
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
            String token1 = Generate.token();
            String token2 = Generate.token();

            // Then
            assertNotEquals("Got identical tokens.", token1, token2);
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
            String salt1 = Generate.salt();
            String salt2 = Generate.salt();

            // Then
            assertNotEquals("Got identical salts.", salt1, salt2);
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
            String password1 = Generate.password(passwordSize);
            String password2 = Generate.password(passwordSize);

            // Then
            assertNotEquals("Got identical passwords.", password1, password2);
        }
    }

}
