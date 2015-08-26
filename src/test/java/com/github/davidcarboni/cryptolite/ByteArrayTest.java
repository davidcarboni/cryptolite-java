package com.github.davidcarboni.cryptolite;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test for {@link ByteArray}.
 *
 * @author David Carboni
 */
public class ByteArrayTest {

    /**
     * Verifies that a byte array can be corectly converted to a hex String
     */
    @Test
    public void shouldConventBytesToHexString() {

        // Given
        final byte[] bytes = new byte[]{0x00, (byte) 0xff, 0x10, 0x08};
        String expected = "00" + "ff" + "10" + "08";

        // When
        String actual = ByteArray.toHexString(bytes);

        // Then
        assertEquals(expected, actual);
    }

    /**
     * Verifies that a hex String can be correctly converted to bytes.
     */
    @Test
    public void shouldConvertHexStringToBytes() {

        // Given
        final byte[] expected = new byte[]{0x00, (byte) 0xff, 0x10, 0x08};
        String hexString = "00" + "ff" + "10" + "08";

        // When
        byte[] actual = ByteArray.fromHexString(hexString);

        // Then
        assertTrue(Arrays.equals(expected, actual));
    }

    /**
     * Verifies that a hex String with a 0x prefix can be correctly converted to
     * bytes.
     */
    @Test
    public void shouldConvertHexStringWithPrefixToBytes() {

        // Given
        final byte[] expected = new byte[]{0x00, (byte) 0xff, 0x10, 0x08};
        String hexString = "0x" + "00" + "ff" + "10" + "08";

        // When
        byte[] actual = ByteArray.fromHexString(hexString);

        // Then
        assertTrue(Arrays.equals(expected, actual));
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.ByteArray#toHexString(byte[])}
     * where the parameter is null.
     */
    @Test
    public void testToHexStringNull() {

        // Given
        byte[] bytes = null;

        // When
        String string = ByteArray.toHexString(bytes);

        // Then
        assertNull(string);
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.ByteArray#toBase64String(byte[])}
     * and
     * {@link com.github.davidcarboni.cryptolite.ByteArray#fromBase64String(String)}
     * .
     */
    @Test
    public void testBase64String() {

        // Given
        final int size = 125;
        byte[] byteArray = Random.bytes(size);

        // When
        String toBase64 = ByteArray.toBase64String(byteArray);
        byte[] fromBase64 = ByteArray.fromBase64String(toBase64);

        // Then
        assertTrue(Arrays.equals(byteArray, fromBase64));
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.ByteArray#toBase64String(byte[])}
     * and
     * {@link com.github.davidcarboni.cryptolite.ByteArray#fromBase64String(String)}
     * where the parameter is null.
     */
    @Test
    public void testBase64StringNull() {

        // Given
        byte[] bytes = null;
        String string = null;

        // When
        String toBase64 = ByteArray.toBase64String(bytes);
        byte[] fromBase64 = ByteArray.fromBase64String(string);

        // Then
        assertNull(toBase64);
        assertNull(fromBase64);
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.ByteArray#fromString(String)} and
     * {@link com.github.davidcarboni.cryptolite.ByteArray#toString(byte[])}.
     */
    @Test
    public void testByteArray() {

        // Given
        String string = "£The quick brown & fox jumpéd over the Lazy dog.";

        // When
        byte[] toByteArray = ByteArray.fromString(string);
        String fromByteArray = ByteArray.toString(toByteArray);

        // Then
        assertEquals(string, fromByteArray);
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.ByteArray#fromString(String)} and
     * {@link com.github.davidcarboni.cryptolite.ByteArray#toString(byte[])}
     * where the parameter is null.
     */
    @Test
    public void testByteArrayNull() {

        // Given
        String string = null;
        byte[] bytes = null;

        // When
        byte[] toByteArray = ByteArray.fromString(string);
        String fromByteArray = ByteArray.toString(bytes);

        // Then
        assertNull(toByteArray);
        assertNull(fromByteArray);
    }

}
