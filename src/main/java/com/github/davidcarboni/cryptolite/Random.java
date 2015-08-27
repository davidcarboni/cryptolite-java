package com.github.davidcarboni.cryptolite;

import org.apache.commons.lang.RandomStringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class provides random functions, such as Salt, ID and password
 * generation. It also allows you to get a singleton {@link SecureRandom}
 * instance.
 *
 * @author David Carboni
 */
public class Random {

    /**
     * The length of IDs: {@value #ID_BITS}.
     */
    public static final int ID_BITS = 256;

    /**
     * The algorithm for the {@link SecureRandom} instance: {@value #ALGORITHM}.
     */
    public static final String ALGORITHM = "SHA1PRNG";

    /**
     * The length of salt values: {@value #SALT_BYTES}.
     */
    public static final int SALT_BYTES = 16;

    // Work out the right number of bytes for random IDs:
    private static final int bitsInAByte = 8;
    private static final int idLengthBytes = ID_BITS / bitsInAByte;

    // Characters for pasword generation:
    private static final String passwordCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * Lazily-instantiated, cached {@link SecureRandom} instance.
     *
     * SecureRandom is thread-safe: <a href=
     * "http://stackoverflow.com/questions/1461568/is-securerandom-thread-safe"
     * >http
     * ://stackoverflow.com/questions/1461568/is-securerandom-thread-safe</a>
     */
    private static SecureRandom secureRandom;

    /**
     * @return A lazily-instantiated, cached {@link SecureRandom} instance for
     * the algorithm {@value #ALGORITHM}. This is a global instance and
     * is thread-safe. The only consideration is whether thread
     * contention could be an issue. See
     * http://stackoverflow.com/questions
     * /1461568/is-securerandom-thread-safe for more details.
     */
    public static SecureRandom getInstance() {

        // Create if necessary:
        if (secureRandom == null) {
            // NB according to the javadoc, getInstance produces an appropriate
            // SecureRandom, which will be seeded on the first call to
            // nextBytes():
            // "Note that the returned instance of SecureRandom has not been
            // seeded. A call to the setSeed method will seed the SecureRandom
            // object.
            // If a call is not made to setSeed, the first call to the nextBytes
            // method will force the SecureRandom object to seed itself."
            try {
                secureRandom = SecureRandom.getInstance(ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unable to find algorithm "
                        + ALGORITHM + " for "
                        + SecureRandom.class.getSimpleName());
            }
        }

        return secureRandom;
    }

    /**
     * Convenience method to instantiate and populate a byte array of the specified
     * length.
     *
     * @param length The length of the array.
     * @return {@link SecureRandom#nextBytes(byte[])}
     */
    public static byte[] bytes(int length) {
        byte[] bytes = new byte[length];
        getInstance().nextBytes(bytes);
        return bytes;
    }

    /**
     * Convenience method to instantiate an {@link InputStream} of random data of the specified
     * length.
     *
     * @param length The length of the stream.
     * @return {@link SecureRandom#nextBytes(byte[])}
     */
    public static InputStream inputStream(final long length) {
        return new InputStream() {
            int count;
            @Override
            public int read() throws IOException {
                if (count++ < length) {
                    return Byte.toUnsignedInt(bytes(1)[0]);
                } else {
                    return -1;
                }
            }
        };
    }

    /**
     * @return A 256-bit (32 byte) random ID as a hexadecimal string.
     */
    public static String id() {
        byte[] idBytes = bytes(idLengthBytes);
        return ByteArray.toHexString(idBytes);
    }

    /**
     * Convenience method to generate a random password.
     *
     * This method no longer uses Apache
     * {@link RandomStringUtils#random(int, int, int, boolean, boolean, char[], java.util.Random)}
     * , because the implementation of that method calls
     * {@link java.util.Random#nextInt()}, which is not overridden by the
     * {@link SecureRandom} returned by {@link #getInstance()}.
     *
     * That means passwords wouldn't be generated using cryptographically strong
     * pseudo random numbers, despite passing a {@link SecureRandom}.
     *
     * @param length The length of the password to be returned.
     * @return A String of the specified length, composed of uppercase letters,
     * lowercase letters and numbers.
     */
    public static String password(int length) {
        StringBuilder result = new StringBuilder();

        while (result.length() < length) {
            byte[] buffer = bytes(length);
            int i = 0;
            do {
                // There are 62 possible password characters,
                // So we mask out the leftmost 2 bits to get a value between 0
                // and 63. That way most indices correspond to a character:
                int index = buffer[i++] & 0x3F;
                if (index < passwordCharacters.length()) {
                    result.append(passwordCharacters.charAt(index));
                }
            } while (result.length() < length && i < buffer.length);
        }

        return result.toString();
    }

    /**
     * Generates a random salt value. If a salt value is needed by an API call,
     * the JavaDoc of that method should reference this method. Other than than,
     * it should not be necessary to call this in normal usage of this library.
     *
     * @return A {@value #SALT_BYTES}-byte random salt value as a base64-encoded
     * string (for easy storage).
     */
    public static String salt() {
        byte[] salt = bytes(SALT_BYTES);
        return ByteArray.toBase64String(salt);
    }
}
