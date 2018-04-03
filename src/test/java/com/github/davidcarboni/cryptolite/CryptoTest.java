package com.github.davidcarboni.cryptolite;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test for {@link Crypto}.
 *
 * @author David Carboni
 */
public class CryptoTest {

    static final Crypto crypto = new Crypto();
    SecretKey key;
    static final String password = "password";

    /**
     * Generates a {@link KeyPair} and instantiates a {@link DigitalSignature}.
     */
    @BeforeClass
    public static void setUpBeforeClass() {
        // Use standard keys to make sure tests run in any environment:
        Keys.useStandardKeys();
    }

    @Before
    public void setup() {
        key = Keys.newSecretKey();
    }

    /**
     * Takes a peek inside the {@link Crypto} instance to verify that the {@link Cipher} is indeed
     * using the algorithm defined by {@link Crypto#CIPHER_NAME}.
     *
     * @throws NoSuchFieldException   {@link NoSuchFieldException}
     * @throws IllegalAccessException {@link IllegalAccessException}
     */
    @Test
    public void testCrypto() throws NoSuchFieldException, IllegalAccessException {

        // Given
        Field cipherField = Crypto.class.getDeclaredField("cipher");
        cipherField.setAccessible(true);
        Cipher cipher = (Cipher) cipherField.get(crypto);

        // Then
        assertEquals(Crypto.CIPHER_NAME, cipher.getAlgorithm());
    }

    /**
     * Verifies that null is returned for null encryption input.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldNotEncryptNullStringWithKey() {

        // Given
        String plaintext = null;

        // When
        String ciphertext = crypto.encrypt(plaintext, key);

        // Then
        assertNull(ciphertext);
    }

    /**
     * Verifies that null is returned for null encryption input.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldNotEncryptNullStringWithPassword() {

        // Given
        String plaintext = null;

        // When
        String ciphertext = crypto.encrypt(plaintext, password);

        // Then
        assertNull(ciphertext);
    }

    /**
     * Verifies that an empty String gets encrypted.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldEncryptEmptyStringWithPassword() {

        // Given
        String plaintext = "";

        // When
        String ciphertext = crypto.encrypt(plaintext, password);

        // Then
        assertNotNull(ciphertext);
        assertFalse(StringUtils.isEmpty(ciphertext));
        assertEquals(plaintext, crypto.decrypt(ciphertext, password));
    }

    /**
     * Verifies that an empty String gets encrypted.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldEncryptEmptyStringWithKey() {

        // Given
        String plaintext = "";

        // When
        String ciphertext = crypto.encrypt(plaintext, key);

        // Then
        assertNotNull(ciphertext);
        assertFalse(StringUtils.isEmpty(ciphertext));
        assertEquals(plaintext, crypto.decrypt(ciphertext, key));
    }

    /**
     * Verifies that the same String gets encrypted differently every time.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldEncryptSameStringDifferentlyWithPassword() {

        // Given
        String plaintext = "The quick brown fox jumped over the lazy dog.";
        // Ignore any newlines:
        String ciphertext1 = crypto.encrypt(plaintext, password).replace("\n", "").replace("\r", "");
        int length = ciphertext1.length();
        boolean[] different = new boolean[length];
        final int maxAttempts = 100;
        int attempt = 0;

        // When
        // Encrypt the same string over and over  until
        // we have seen a different character at every position:
        while (ArrayUtils.contains(different, false) && attempt++ < maxAttempts) {

            String ciphertext2 = crypto.encrypt(plaintext, password).replace("\n", "").replace("\r", "");
            for (int i = 0; i < length; i++) {
                // Compare each character, but ignore base-64 padding:
                different[i] |= ciphertext1.charAt(i) != ciphertext2.charAt(i) || ciphertext1.charAt(i) == '=';
            }
        }

        // Then
        assertFalse(ArrayUtils.contains(different, false));
    }

    /**
     * Verifies that the same String gets encrypted differently every time.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldEncryptSameStringDifferentlyWithKey() {

        // Given
        String plaintext = "The quick brown fox jumped over the lazy dog.";
        // Ignore any newlines:
        String ciphertext1 = crypto.encrypt(plaintext, key).replace("\n", "").replace("\r", "");
        int length = ciphertext1.length();
        boolean[] different = new boolean[length];
        final int maxAttempts = 100;
        int attempt = 0;

        // When
        // Encrypt the same string over and over  until
        // we have seen a different character at every position:
        while (ArrayUtils.contains(different, false) && attempt++ < maxAttempts) {

            String ciphertext2 = crypto.encrypt(plaintext, key).replace("\n", "").replace("\r", "");
            for (int i = 0; i < length; i++) {
                // Compare each character, but ignore base-64 padding:
                different[i] |= ciphertext1.charAt(i) != ciphertext2.charAt(i) || ciphertext1.charAt(i) == '=';
            }
        }

        // Then
        assertFalse(ArrayUtils.contains(different, false));
    }

    /**
     * Verifies that null is returned for null decryption input.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldNotDecryptNullStringWithPassword() {

        // Given
        String ciphertext = null;

        // When
        String plaintext = crypto.decrypt(ciphertext, password);

        // Then
        assertNull(plaintext);
    }

    /**
     * Verifies that null is returned for null decryption input.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldNotDecryptNullStringWithKey() {

        // Given
        String ciphertext = null;

        // When
        String plaintext = crypto.decrypt(ciphertext, key);

        // Then
        assertNull(plaintext);
    }

    /**
     * Verifies that an empty string is returned for empty decryption input.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldDecryptEmptyStringWithPassword() {

        // Given
        String ciphertext = "";

        // When
        String plaintext = crypto.decrypt(ciphertext, password);

        // Then
        assertEquals(ciphertext, plaintext);
    }

    /**
     * Verifies that an empty string is returned for empty decryption input.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldDecryptEmptyStringWithKey() {

        // Given
        String ciphertext = "";

        // When
        String plaintext = crypto.decrypt(ciphertext, key);

        // Then
        assertEquals(ciphertext, plaintext);
    }

    /**
     * Verifies that decryption input which is too short to contain an initialisation vector throws
     * an exception.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotDecryptTooShortStringWithPassword() {

        // Given
        byte[] bytes = new byte[1];
        String ciphertext = ByteArray.toBase64(bytes);

        // When
        crypto.decrypt(ciphertext, password);

        // Then
        // We should get an IllegalArgumentException because
        // the input is too short to contain an IV, so does
        // not match the expected format of [IV][data]
    }

    /**
     * Verifies that decryption input which is too short to contain an initialisation vector throws
     * an exception.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotDecryptTooShortStringWithKey() {

        // Given
        byte[] bytes = new byte[1];
        String ciphertext = ByteArray.toBase64(bytes);

        // When
        crypto.decrypt(ciphertext, key);

        // Then
        // We should get an IllegalArgumentException because
        // the input is too short to contain an IV, so does
        // not match the expected format of [IV][data]
    }

    /**
     * Verifies that decryption is successful and consistent, even for different ciphertext Strings
     * - ie if you encrypt something twice, the encrypted data should be different each time, but
     * should decrypt back to the same thing.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldDecryptDifferentStringsToSamePlaintextWithPassword() {

        // Given
        String input = "My love is like a red, red rose.";
        String ciphertext1 = crypto.encrypt(input, password);
        String ciphertext2;
        do {
            // Ensure we have a different String:
            ciphertext2 = crypto.encrypt(input, password);
        } while (ciphertext1.equals(ciphertext2));

        // When
        String plaintext1 = crypto.decrypt(ciphertext1, password);
        String plaintext2 = crypto.decrypt(ciphertext2, password);

        // Then
        assertEquals(input, plaintext1);
        assertEquals(plaintext1, plaintext2);
    }

    /**
     * Verifies that decryption is successful and consistent, even for different ciphertext Strings
     * - ie if you encrypt something twice, the encrypted data should be different each time, but
     * should decrypt back to the same thing.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.lang.String, javax.crypto.SecretKey)}.
     */
    @Test
    public void shouldDecryptDifferentStringsToSamePlaintextWithKey() {

        // Given
        String input = "My love is like a red, red rose.";
        String ciphertext1 = crypto.encrypt(input, key);
        String ciphertext2;
        do {
            // Ensure we have a different String:
            ciphertext2 = crypto.encrypt(input, key);
        } while (ciphertext1.equals(ciphertext2));

        // When
        String plaintext1 = crypto.decrypt(ciphertext1, key);
        String plaintext2 = crypto.decrypt(ciphertext2, key);

        // Then
        assertEquals(input, plaintext1);
        assertEquals(plaintext1, plaintext2);
    }

    /**
     * Verifies that attempting to encrypt a null output stream just returns null.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
     * .
     *
     * @throws IOException {@link IOException}
     */
    @Test
    public void shouldNotEncryptNullOutputStreamWithPassword() throws IOException {

        // Given
        OutputStream destination = null;

        // When
        OutputStream encryptor = crypto.encrypt(destination, password);

        // Then
        assertNull(encryptor);
    }

    /**
     * Verifies that attempting to encrypt a null output stream just returns null.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
     * .
     *
     * @throws IOException {@link IOException}
     */
    @Test
    public void shouldNotEncryptNullOutputStreamWithKey() throws IOException {

        // Given
        OutputStream destination = null;

        // When
        OutputStream encryptor = crypto.encrypt(destination, key);

        // Then
        assertNull(encryptor);
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
     * .
     *
     * @throws IOException {@link IOException}
     */
    @Test
    public void shouldEncryptSameDataDifferentlyWithPassword() throws IOException {

        // Given
        byte[] data = ("Three french hens, two turtle doves " + "and a partridge in a pear tree.").getBytes("UTF8");
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        int size = IOUtils.copy(new ByteArrayInputStream(data), crypto.encrypt(destination, password));
        byte[] ciphertext1 = destination.toByteArray();
        boolean[] different = new boolean[size];
        final int maxAttempts = 100;
        int attempt = 0;

        // When
        // Encrypt the same data over and over until
        // we have seen a different byte at every position:
        while (ArrayUtils.contains(different, false) && attempt++ < maxAttempts) {

            destination = new ByteArrayOutputStream();
            IOUtils.copy(new ByteArrayInputStream(data), crypto.encrypt(destination, password));
            byte[] ciphertext2 = destination.toByteArray();
            for (int i = 0; i < size; i++) {
                // Compare each byte:
                different[i] |= ciphertext1[i] != ciphertext2[i];
            }
        }

        // Then
        assertFalse(ArrayUtils.contains(different, false));
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#encrypt(java.io.OutputStream, javax.crypto.SecretKey)}
     * .
     *
     * @throws IOException {@link IOException}
     */
    @Test
    public void shouldEncryptSameDataDifferentlyWithKey() throws IOException {

        // Given
        byte[] data = ("Three french hens, two turtle doves " + "and a partridge in a pear tree.").getBytes("UTF8");
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        int size = IOUtils.copy(new ByteArrayInputStream(data), crypto.encrypt(destination, key));
        byte[] ciphertext1 = destination.toByteArray();
        boolean[] different = new boolean[size];
        final int maxAttempts = 100;
        int attempt = 0;

        // When
        // Encrypt the same data over and over until
        // we have seen a different byte at every position:
        while (ArrayUtils.contains(different, false) && attempt++ < maxAttempts) {

            destination = new ByteArrayOutputStream();
            IOUtils.copy(new ByteArrayInputStream(data), crypto.encrypt(destination, key));
            byte[] ciphertext2 = destination.toByteArray();
            for (int i = 0; i < size; i++) {
                // Compare each byte:
                different[i] |= ciphertext1[i] != ciphertext2[i];
            }
        }

        // Then
        assertFalse(ArrayUtils.contains(different, false));
    }

    /**
     * Verifies that decryption of differing ciphertext streams result in the same plaintext - ie if
     * you encrypt something twice, the encrypted data should be different each time, but should
     * decrypt back to the same thing.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.io.InputStream, javax.crypto.SecretKey)} .
     *
     * @throws IOException {@link IOException}
     */
    @Test
    public void shouldDecryptDifferentStreamsToSamePlaintextWithPassword() throws IOException {

        // Given
        byte[] input = ("It's really important, you know, to take care of other peoples' stuff "
                + "if they are trusting you to look after it.").getBytes("UTF8");
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        OutputStream encryptor;
        encryptor = crypto.encrypt(destination, password);
        IOUtils.copy(new ByteArrayInputStream(input), encryptor);
        encryptor.close();
        byte[] ciphertext1 = destination.toByteArray();
        byte[] ciphertext2;
        do {
            // Ensure we have a different byte array:
            destination = new ByteArrayOutputStream();
            encryptor = crypto.encrypt(destination, password);
            IOUtils.copy(new ByteArrayInputStream(input), encryptor);
            encryptor.close();
            ciphertext2 = destination.toByteArray();
        } while (Arrays.equals(ciphertext1, ciphertext2));

        // When
        destination = new ByteArrayOutputStream();
        IOUtils.copy(crypto.decrypt(new ByteArrayInputStream(ciphertext1), password), destination);
        byte[] plaintext1 = destination.toByteArray();
        destination = new ByteArrayOutputStream();
        IOUtils.copy(crypto.decrypt(new ByteArrayInputStream(ciphertext2), password), destination);
        byte[] plaintext2 = destination.toByteArray();

        // Then
        assertTrue(Arrays.equals(input, plaintext1));
        assertTrue(Arrays.equals(plaintext1, plaintext2));
    }

    /**
     * Verifies that decryption of differing ciphertext streams result in the same plaintext - ie if
     * you encrypt something twice, the encrypted data should be different each time, but should
     * decrypt back to the same thing.
     * <p>
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.Crypto#decrypt(java.io.InputStream, javax.crypto.SecretKey)} .
     *
     * @throws IOException {@link IOException}
     */
    @Test
    public void shouldDecryptDifferentStreamsToSamePlaintextWithKey() throws IOException {

        // Given
        byte[] input = ("It's really important, you know, to take care of other peoples' stuff "
                + "if they are trusting you to look after it.").getBytes("UTF8");
        ByteArrayOutputStream destination = new ByteArrayOutputStream();
        OutputStream encryptor;
        encryptor = crypto.encrypt(destination, key);
        IOUtils.copy(new ByteArrayInputStream(input), encryptor);
        encryptor.close();
        byte[] ciphertext1 = destination.toByteArray();
        byte[] ciphertext2;
        do {
            // Ensure we have a different byte array:
            destination = new ByteArrayOutputStream();
            encryptor = crypto.encrypt(destination, key);
            IOUtils.copy(new ByteArrayInputStream(input), encryptor);
            encryptor.close();
            ciphertext2 = destination.toByteArray();
        } while (Arrays.equals(ciphertext1, ciphertext2));

        // When
        destination = new ByteArrayOutputStream();
        IOUtils.copy(crypto.decrypt(new ByteArrayInputStream(ciphertext1), key), destination);
        byte[] plaintext1 = destination.toByteArray();
        destination = new ByteArrayOutputStream();
        IOUtils.copy(crypto.decrypt(new ByteArrayInputStream(ciphertext2), key), destination);
        byte[] plaintext2 = destination.toByteArray();

        // Then
        assertTrue(Arrays.equals(input, plaintext1));
        assertTrue(Arrays.equals(plaintext1, plaintext2));
    }
}
