package com.github.davidcarboni.cryptolite;

import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests for byte array conversions.
 *
 * @author David Carboni
 */
public class ByteArrayTest {

    /**
     * Verifies a byte array can be correctly converted to a hex String and back again.
     */
    @Test
    public void testHex() {

        // Given
        byte[] data = Generate.byteArray(100);

        // When
        // We convert to hex and back again
        String hex = ByteArray.toHex(data);
        byte[] backAgain = ByteArray.fromHex(hex);

        // Then
        // The end result should match the input
        assertArrayEquals(data, backAgain);
    }

    /**
     * Verifies that null is gracefully handled.
     */
    @Test
    public void testHexNull() {

        // When
        // We attempt conversion
        String s = ByteArray.toHex(null);
        byte[] b = ByteArray.fromHex(null);

        // Then
        // No error should occur and we should have null results
        assertNull(s);
        assertNull(b);
    }

    /**
     * Verifies a byte array can be correctly converted to base64 and back again.
     */
    @Test
    public void testBase64() {

        // Given
        byte[] data = Generate.byteArray(100);

                // When
        // We convert to hex and back again
        String base64 = ByteArray.toBase64(data);
        byte[] backAgain = ByteArray.fromBase64(base64);

        // Then
        // The end result should match the input
        assertArrayEquals(data, backAgain);
    }

    /**
     * Verifies that null is gracefully handled.
     */
    @Test
    public void testBase64Null() {

        // When
        // We attempt conversion
        String s = ByteArray.toBase64(null);
        byte[] b = ByteArray.fromBase64(null);

        // Then
        // No error should occur and we should have null results
        assertNull(s);
        assertNull(b);
    }

    /**
     * Verifies a byte array can be correctly converted to a string and back again.
     */
    @Test
    public void testString() {

        // Given
        byte[] data = "Mary had a little Café".getBytes(StandardCharsets.UTF_8);

        // When
        // We convert to string and back again
        String string = ByteArray.toString(data);
        byte[] backAgain = ByteArray.fromString(string);

        // Then
        // The end result should match the input
        assertArrayEquals(data, backAgain);
    }

    /**
     * Verifies that null is gracefully handled.
     */
    @Test
    public void testStringNull() {

        // When
        // We attempt conversion
        String s = ByteArray.toString(null);
        byte[] b = ByteArray.fromString(null);

        // Then
        // No error should occur and we should have null results
        assertNull(s);
        assertNull(b);
    }

}
