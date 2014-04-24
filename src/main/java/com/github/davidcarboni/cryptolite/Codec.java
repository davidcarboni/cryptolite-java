package com.github.davidcarboni.cryptolite;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * 
 * This class provides the ability to convert a byte array to Base-64 and back,
 * or to a hexadecimal string for printing out.
 * <p>
 * It also provides for converting text String objects to and from a byte array.
 * 
 * @author David Carboni
 * 
 */
public class Codec {

	/**
	 * The encoding to use for string operations.
	 */
	public static final String ENCODING = "UTF8";

	/**
	 * Renders the given byte array as a hex String. This is a convenience
	 * method useful for checking values during development.
	 * <p>
	 * Internally, this checks for null and then calls the Apache commons-codec
	 * method {@link Hex#encodeHexString(byte[])}.
	 * 
	 * @param bytes
	 *            The array to be rendered.
	 * @return A string representation of the byte array.
	 */
	public static String toHexString(byte[] bytes) {

		if (bytes == null) {
			return null;
		}

		return Hex.encodeHexString(bytes);
	}

	/**
	 * With thanks to StackOverflow: <a href=
	 * "http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java"
	 * >Convert a string representation of a hex dump to a byte array using
	 * Java?</a>
	 * 
	 * @param hex
	 *            The hex String to parse. If it starts with 0x, this will be
	 *            ignored automatically.
	 * @return A byte array, as parsed from the given String
	 */
	public static byte[] fromHexString(String hex) {
		String data = hex;
		if (hex.length() > 1 && (hex.charAt(1) == 'x' || hex.charAt(1) == 'X')) {
			data = hex.substring(2);
		}
		int len = data.length();
		byte[] result = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			result[i / 2] = (byte) ((Character.digit(data.charAt(i), 16) << 4) + Character
					.digit(data.charAt(i + 1), 16));
		}
		return result;
	}

	/**
	 * Encodes the given byte array as a base-64 String.
	 * 
	 * Internally, this checks for null and then calls the Apache commons-codec
	 * method {@link Base64#encodeBase64String(byte[])}.
	 * 
	 * @param bytes
	 *            The array to be encoded.
	 * @return The byte array encoded using base-64.
	 */
	public static String toBase64String(byte[] bytes) {

		if (bytes == null) {
			return null;
		}

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

		if (base64 == null) {
			return null;
		}

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
	 * @return The String represented by the given bytes.
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
