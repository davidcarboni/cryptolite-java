package com.github.davidcarboni.cryptolite;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test for {@link ByteArray}.
 *
 * @author David Carboni
 */
public class ByteArrayTest {

    static byte[] data;

    @BeforeClass
    public static void setup() throws UnsupportedEncodingException {
        data = "Mary had a little Café".getBytes("UTF8");
    }

    /**
     * Verifies a byte array can be correctly converted to a hex String and back again.
     */
    @Test
    public void testHex() {

        // Given
        // The byte array from setup

        // When
        // We convert to hex and back again
        String hexString = ByteArray.toHexString(data);
        byte[] backAgain = ByteArray.fromHexString(hexString);

        // Then
        // The end result should match the input
        assertArrayEquals(data, backAgain);
    }

    /**
     * Verifies that a hex String with a 0x prefix can be correctly converted to
     * bytes.
     */
    @Test
    public void testHexPrefix() {

        // Given
        // A hex string with a 0x prefix
        String hexString = "0x" + ByteArray.toHexString(data);

        // When
        // We attempt to convert to a byte array
        byte[] actual = ByteArray.fromHexString(hexString);

        // Then
        // No error should occur
        assertArrayEquals(data, actual);
    }

    /**
     * Verifies that null is gracefully handled.
     */
    @Test
    public void testHexNull() {

        // When
        // We attempt conversion
        String s = ByteArray.toHexString(null);
        byte[] b = ByteArray.fromHexString(null);

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
        // The byte array from setup

        // When
        // We convert to hex and back again
        String base64String = ByteArray.toBase64String(data);
        byte[] backAgain = ByteArray.fromBase64String(base64String);

        // Then
        // The end result should match the input
        assertTrue(Arrays.equals(data, backAgain));
    }

    /**
     * Verifies that null is gracefully handled.
     */
    @Test
    public void testBase64Null() {

        // When
        // We attempt conversion
        String s = ByteArray.toBase64String(null);
        byte[] b = ByteArray.fromBase64String(null);

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
        // The byte array from setup

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
