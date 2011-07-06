/**
 * 
 */
package org.workdocx.cryptolite;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;

/**
 * @author david
 * 
 */
public class Codec {

	/**
	 * The encoding to use for string operations.
	 */
	public static final String ENCODING = "UTF8";

	private static final int mask = 0xff;
	private static final int shift = 0x100;
	private static final int radix = 16;

	/**
	 * Renders the given byte array as a hex String.
	 * 
	 * @param bytes
	 *            The array to be rendered.
	 * @return A string representation of the byte array.
	 */
	public static String toHexString(byte[] bytes) {

		if (bytes == null) {
			return null;
		}

		StringBuilder result = new StringBuilder();

		for (byte b : bytes) {
			result.append(Integer.toString((b & mask) + shift, radix).substring(1));
		}

		return result.toString();
	}

	/**
	 * Encodes the given byte array as a base-64 String.
	 * 
	 * @param bytes
	 *            The array to be encoded.
	 * @return The byte array encoded using base-64.
	 */
	public static String toBase64String(byte[] bytes) {
		return Base64.encodeBase64String(bytes);
	}

	/**
	 * Decodes the given base-64 string into a byte array.
	 * 
	 * @param base64
	 *            A base-64 encoded string.
	 * @return The decoded byte array.
	 */
	public static byte[] fromBase64String(String base64) {
		return Base64.decodeBase64(base64);
	}

	/**
	 * Converts the given String to a byte array using {@value #ENCODING}.
	 * 
	 * @param string
	 *            The String to be converted to a byte array.
	 * @return A byte array representing the String.
	 */
	public static byte[] toByteArray(String string) {

		if (string == null) {
			return null;
		}

		try {
			return string.getBytes(ENCODING);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Error converting String to byte array using encoding " + ENCODING);
		}
	}

	/**
	 * Converts the given byte array to a String using {@value #ENCODING}.
	 * 
	 * @param bytes
	 *            The byte array to be converted to a String.
	 * @return A byte array representing the String.
	 */
	public static String fromByteArray(byte[] bytes) {

		if (bytes == null) {
			return null;
		}

		try {
			return new String(bytes, ENCODING);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Error converting byte array to String using encoding " + ENCODING);
		}
	}
}
