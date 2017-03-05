package com.github.davidcarboni.cryptolite;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;

/**
 * This class provides the ability to convert Strings, Base-64 and hexadecimal
 * to a byte array and vice versa.
 * <p>
 * Cryptography is mainly about manipulating byte arrays, so this class provides
 * the translations you need:
 * <ul>
 * <li>Plain-text strings need to be converted to a byte array for encryption
 * and, after decryption, need to be converted from a byte array back to a
 * String. This is done using {@value #ENCODING} encoding.</li>
 * <li>Encrypted byte arrays look like random bytes, which means they can't be
 * reliably represented as a String. The best way to represent arbitrary bytes
 * as a String is using Base-64. This class lets you convert a byte array of
 * encrypted data to Base-64 so it can be easily stored and back again so it can
 * be decrypted</li>
 * <li>Finally, this class also allows you to transform a byte array to a
 * hexadecimal String and back again. This is most useful in development when
 * you need to print out values to see what's going on. Conversion from
 * hexadecimal to byte array is occasionally useful, but chances are you'll use
 * <code>byte[]</code> to hex most of the time.</li>
 * </ul>
 *
 * @author David Carboni
 */
public class ByteArray {

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
     * @param byteArray The byte array to be rendered.
     * @return A hex string representation of the byte array.
     */
    public static String toHexString(byte[] byteArray) {

        String result = null;
        if (byteArray != null) {
            result = Hex.encodeHexString(byteArray);
        }
        return result;
    }

    /**
     * Converts the given hex string to a byte array.
     * <p>
     * With thanks to StackOverflow: <a href=
     * "http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java"
     * >Convert a string representation of a hex dump to a byte array using
     * Java?</a>
     *
     * @param hex The hex String to parse. If it starts with 0x, this will be
     *            ignored automatically.
     * @return A byte array, as parsed from the given String
     */
    public static byte[] fromHexString(String hex) {
        byte[] result = null;
        if (hex != null) {
            String data = hex;
            if (hex.length() > 1 && (hex.charAt(1) == 'x' || hex.charAt(1) == 'X')) {
                data = hex.substring(2);
            }
            int len = data.length();
            result = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                result[i / 2] = (byte) ((Character.digit(data.charAt(i), 16) << 4) + Character
                        .digit(data.charAt(i + 1), 16));
            }
        }
        return result;
    }

    /**
     * Encodes the given byte array as a base-64 String.
     * <p>
     * Internally, this checks for null and then calls the Apache commons-codec
     * method {@link Base64#encodeBase64String(byte[])}.
     *
     * @param byteArray The byte array to be encoded.
     * @return The byte array encoded using base-64.
     */
    public static String toBase64String(byte[] byteArray) {

        String result = null;
        if (byteArray != null) {
            result = Base64.encodeBase64String(byteArray);
        }
        return result;
    }

    /**
     * Decodes the given base-64 string into a byte array.
     *
     * @param base64 A base-64 encoded string.
     * @return The decoded byte array.
     */
    public static byte[] fromBase64String(String base64) {

        byte[] result = null;
        if (base64 != null) {
            result = Base64.decodeBase64(base64);
        }
        return result;
    }

    /**
     * Converts the given String to a byte array using {@value #ENCODING}.
     *
     * @param string The String to be converted to a byte array.
     * @return A byte array representing the String.
     */
    public static byte[] fromString(String string) {

        byte[] result = null;
        if (string != null) {
            try {
                result = string.getBytes(ENCODING);
            } catch (UnsupportedEncodingException e) {
                throw new IllegalArgumentException("Error converting String to byte array using encoding " + ENCODING);
            }
        }
        return result;
    }

    /**
     * Converts the given byte array to a String using {@value #ENCODING}.
     *
     * @param byteArray The byte array to be converted to a String.
     * @return The String represented by the given bytes.
     */
    public static String toString(byte[] byteArray) {

        String result = null;
        if (byteArray != null) {
            try {
                result = new String(byteArray, ENCODING);
            } catch (UnsupportedEncodingException e) {
                throw new IllegalArgumentException("Error converting byte array to String using encoding " + ENCODING);
            }
        }
        return result;
    }
}
