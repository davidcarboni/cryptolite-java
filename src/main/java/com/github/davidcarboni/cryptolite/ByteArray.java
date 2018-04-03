package com.github.davidcarboni.cryptolite;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;

/**
 * The ByteArray class provides the ability to convert byte arrays to
 * Strings, Base-64 and hexadecimal and vice versa.
 * <p>
 * Cryptography is mainly about manipulating byte arrays, so this class provides
 * the different translations you need:
 * <ul>
 * <li>Plain-text strings need to be converted to a byte array for encryption
 * and, after decryption, need to be converted from a byte array back to a
 * String.</li>
 * <li>Encrypted byte arrays look like random bytes, which means they can't be
 * reliably represented as a String. The simplest way to represent arbitrary bytes
 * as a String is using Base-64. This class lets you convert a byte array of
 * encrypted data to Base-64 so it can be easily stored and back again so it can
 * be decrypted.</li>
 * <li>Finally, this class also allows you to transform a byte array to a
 * hexadecimal String and back again. This is most useful in development when
 * you need to print out values to see what's going on. Conversion from
 * hexadecimal to byte array is occasionally useful, but chances are you'll use
 * <code>byte[]</code> to hex most of the time.</li>
 * </ul>
 * <p>
 * The naming convention for methods is set up from the point of view of
 * a byte array. For example, a byte array can go:
 *
 * <pre>{@link #toHex(byte[])}</pre>
 * <p>
 * and back:
 *
 * <pre>{@link #fromHex(String)}</pre>
 * <p>
 * The same pattern is used for each pair of methods (to/from hex, base64 and string).
 *
 * @author David Carboni
 */
public class ByteArray {

    /**
     * Renders the given byte array as a hex String.
     * <p>
     * This is a convenience method useful for testing values during development.
     *
     * @param byteArray The byte array to be represented in hex.
     * @return A hex string representation of the byte array.
     */
    public static String toHex(byte[] byteArray) {

        String result = null;
        if (byteArray != null) {
            result = Hex.encodeHexString(byteArray);
        }
        return result;
    }

    /**
     * Converts the given hex string to a byte array.
     * <p>
     * This is a convenience method useful for testing values during development.
     *
     * @param hexString The hex String to parse to bytes.
     * @return A byte array, as parsed from the given String
     */
    public static byte[] fromHex(String hexString) {
        byte[] result = null;
        if (hexString != null) {
            try {
                // With thanks to StackOverflow:
                // http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
                result = Hex.decodeHex(hexString.toCharArray());
            } catch (DecoderException e) {
                throw new IllegalArgumentException("Could not parse this value as hex: " + hexString);
            }
        }
        return result;
    }

    /**
     * Encodes the given byte array as a base-64 String.
     *
     * @param byteArray The byte array to be encoded.
     * @return The byte array encoded using base-64.
     */
    public static String toBase64(byte[] byteArray) {

        String result = null;
        if (byteArray != null) {
            result = Base64.encodeBase64String(byteArray);
        }
        return result;
    }

    /**
     * Decodes the given base-64 string to a byte array.
     *
     * @param base64String A base-64 encoded string.
     * @return The decoded byte array.
     */
    public static byte[] fromBase64(String base64String) {

        byte[] result = null;
        if (base64String != null) {
            result = Base64.decodeBase64(base64String);
        }
        return result;
    }

    /**
     * Converts the given byte array to a String.
     *
     * @param byteArray The byte array to be converted to a String.
     * @return The String represented by the given bytes.
     */
    public static String toString(byte[] byteArray) {

        String result = null;
        if (byteArray != null) {
            result = new String(byteArray, StandardCharsets.UTF_8);
        }
        return result;
    }

    /**
     * Converts the given String to a byte array.
     *
     * @param unicodeString The String to be converted to a byte array.
     * @return A byte array representing the String.
     */
    public static byte[] fromString(String unicodeString) {

        byte[] result = null;
        if (unicodeString != null) {
            result = unicodeString.getBytes(StandardCharsets.UTF_8);
        }
        return result;
    }
}
