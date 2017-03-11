package com.github.davidcarboni.cryptolite;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;

/**
 * This class provides the ability to convert Strings, Base-64 and hexadecimal
 * to a byte array and vice versa.
 * <p>
 * Cryptography is mainly about manipulating byte arrays, so this class provides
 * the translations you need:
 * <ul>
 * <li>Plain-text strings need to be converted to a byte array for encryption
 * and, after decryption, need to be converted from a byte array back to a
 * String.</li>
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
 * <p>
 * The naming convention for methods is set up from the point of a byte array.
 * For example, a byte array can go:
 * {@code to_hex_string}
 * and back:
 * {@code from_hex_string}
 * The same pattern is used for each pair of methods (hex, base64 and string).
 *
 * @author David Carboni
 */
public class ByteArray {

    /**
     * Renders the given byte array as a hex String. This is a convenience
     * method useful for checking values during development.
     * <p>
     * Internally, this checks for null and then calls the Apache commons-codec
     * method {@link Hex#encodeHexString(byte[])}.
     *
     * @param bytes The byte array to be rendered.
     * @return A hex string representation of the byte array.
     */
    public static String toHexString(byte[] bytes) {

        String result = null;
        if (bytes != null) {
            result = Hex.encodeHexString(bytes);
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
            int len = hex.length();
            result = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                result[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character
                        .digit(hex.charAt(i + 1), 16));
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
     * @param bytes The byte array to be encoded.
     * @return The byte array encoded using base-64.
     */
    public static String toBase64String(byte[] bytes) {

        String result = null;
        if (bytes != null) {
            result = Base64.encodeBase64String(bytes);
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
     * Converts the given byte array to a String.
     *
     * @param bytes The byte array to be converted to a String.
     * @return The String represented by the given bytes.
     */
    public static String toString(byte[] bytes) {

        String result = null;
        if (bytes != null) {
            result = new String(bytes, StandardCharsets.UTF_8);
        }
        return result;
    }

    /**
     * Converts the given String to a byte array.
     *
     * @param unicode The String to be converted to a byte array.
     * @return A byte array representing the String.
     */
    public static byte[] fromString(String unicode) {

        byte[] result = null;
        if (unicode != null) {
            result = unicode.getBytes(StandardCharsets.UTF_8);
        }
        return result;
    }
}
