package com.github.davidcarboni.cryptolite;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

/**
 * 
 * Test for {@link Codec}.
 * 
 * @author David Carboni
 * 
 */
public class CodecTest {

	/**
	 * Test method for
	 * {@link com.github.davidcarboni.cryptolite.Codec#toHexString(byte[])}.
	 */
	@Test
	public void testToHexString() {

		// Given
		final byte[] bytes = new byte[] { 0x00, (byte) 0xff, 0x10, 0x08 };
		String expected = "00" + "ff" + "10" + "08";

		// When
		String actual = Codec.toHexString(bytes);

		// Then
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link com.github.davidcarboni.cryptolite.Codec#toHexString(byte[])}
	 * where the parameter is null.
	 */
	@Test
	public void testToHexStringNull() {

		// Given
		byte[] bytes = null;

		// When
		String string = Codec.toHexString(bytes);

		// Then
		assertNull(string);
	}

	/**
	 * Test method for
	 * {@link com.github.davidcarboni.cryptolite.Codec#toBase64String(byte[])}
	 * and
	 * {@link com.github.davidcarboni.cryptolite.Codec#fromBase64String(String)}
	 * .
	 */
	@Test
	public void testBase64String() {

		// Given
		final int size = 125;
		byte[] byteArray = Random.nextBytes(size);

		// When
		String toBase64 = Codec.toBase64String(byteArray);
		byte[] fromBase64 = Codec.fromBase64String(toBase64);

		// Then
		assertTrue(Arrays.equals(byteArray, fromBase64));
	}

	/**
	 * Test method for
	 * {@link com.github.davidcarboni.cryptolite.Codec#toBase64String(byte[])}
	 * and
	 * {@link com.github.davidcarboni.cryptolite.Codec#fromBase64String(String)}
	 * where the parameter is null.
	 */
	@Test
	public void testBase64StringNull() {

		// Given
		byte[] bytes = null;
		String string = null;

		// When
		String toBase64 = Codec.toBase64String(bytes);
		byte[] fromBase64 = Codec.fromBase64String(string);

		// Then
		assertNull(toBase64);
		assertNull(fromBase64);
	}

	/**
	 * Test method for
	 * {@link com.github.davidcarboni.cryptolite.Codec#toByteArray(String)} and
	 * {@link com.github.davidcarboni.cryptolite.Codec#fromByteArray(byte[])}.
	 */
	@Test
	public void testByteArray() {

		// Given
		String string = "£The quick brown & fox jumpéd over the Lazy dog.";

		// When
		byte[] toByteArray = Codec.toByteArray(string);
		String fromByteArray = Codec.fromByteArray(toByteArray);

		// Then
		assertEquals(string, fromByteArray);
	}

	/**
	 * Test method for
	 * {@link com.github.davidcarboni.cryptolite.Codec#toByteArray(String)} and
	 * {@link com.github.davidcarboni.cryptolite.Codec#fromByteArray(byte[])}
	 * where the parameter is null.
	 */
	@Test
	public void testByteArrayNull() {

		// Given
		String string = null;
		byte[] bytes = null;

		// When
		byte[] toByteArray = Codec.toByteArray(string);
		String fromByteArray = Codec.fromByteArray(bytes);

		// Then
		assertNull(toByteArray);
		assertNull(fromByteArray);
	}

}
