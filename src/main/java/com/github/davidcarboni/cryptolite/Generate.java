package com.github.davidcarboni.cryptolite;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Generates things that need to be random,
 * including salt, token and password values.
 *
 * @author David Carboni
 */
public class Generate {

    /**
     * The length for tokens.
     */
    public static final int TOKEN_BITS = 256;

    /**
     * The length for salt values.
     */
    public static final int SALT_BYTES = 16;

    /**
     * The algorithm for the {@link SecureRandom} instance.
     */
    public static final String ALGORITHM = "SHA1PRNG";

    // Work out the right number of bytes for random tokens:
    private static final int tokenLengthBytes = TOKEN_BITS / 8;

    // Characters for pasword generation:
    private static final String passwordCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * A {@link SecureRandom} instance for the algorithm {@value #ALGORITHM}.
     * <p>
     * This is a global instance and is thread-safe.
     * <p>
     * The only consideration is whether thread contention could be an issue.
     *
     * @see <a href="http://stackoverflow.com/questions/1461568/is-securerandom-thread-safe">
     * http://stackoverflow.com/questions/1461568/is-securerandom-thread-safe</a>
     */
    private static SecureRandom secureRandom;

    static {
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
            throw new IllegalStateException("Algorithm unavailable: " + ALGORITHM, e);
        }
    }

    /**
     * Instantiates and populates a byte array of the specified length.
     *
     * @param length The length of the array.
     * @return {@link SecureRandom#nextBytes(byte[])}
     */
    public static byte[] byteArray(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a random token.
     *
     * @return A 256-bit (32 byte) random token as a hexadecimal string.
     */
    public static String token() {
        byte[] tokenBytes = byteArray(tokenLengthBytes);
        return ByteArray.toHex(tokenBytes);
    }

    /**
     * Generates a random password.
     *
     * @param length The length of the password to be returned.
     * @return A password of the specified length, selected from {@link #passwordCharacters}.
     */
    public static String password(int length) {
        StringBuilder result = new StringBuilder();

        byte[] values = byteArray(length);
        // We use a modulus of an increasing index rather than of the byte values
        // to avoid certain characters coming up more often.
        int index = 0;

        for (int i = 0; i < length; i++) {
            index += (values[i] & 0xff);
            index = index % passwordCharacters.length();
            result.append(passwordCharacters.charAt(index));
        }

        return result.toString();
    }

    /**
     * Generates a random salt value.
     * <p>
     * If a salt value is needed by an API call,
     * the documentation of that method should reference this method. Other than than,
     * it should not be necessary to call this in normal usage of this library.
     *
     * @return A random salt value of SALT_BYTES length, as a base64-encoded
     * string (for easy storage).
     */
    public static String salt() {
        byte[] salt = byteArray(SALT_BYTES);
        return ByteArray.toBase64(salt);
    }


}
