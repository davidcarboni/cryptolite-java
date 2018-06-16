package com.github.davidcarboni.cryptolite;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * This class provides encryption and decryption of Strings and streams.
 * <p>
 * This class uses the AES algorithm in CTR mode. This avoids the need
 * to select a good algorithm and mode for encryption and allows the caller to
 * just request encryption and decryption operations.
 * <p>
 * Some effort has been invested in choosing these values so that they are
 * suitable for the needs of a web application:
 * <ul>
 * <li>AES cipher: NIST standard for the transmission of classified US
 * government data.</li>
 * <li>CTR cipher mode: NIST standard cipher mode.</li>
 * <li>No padding: the CTR cipher mode is a "streaming" mode and therefore does
 * not require padding.</li>
 * <li>Inline initialisation vector: this avoids the need to handle the IV as an
 * additional out-of-band parameter.</li>
 * </ul>
 * <p>
 * Notes on background information used in selecting the cipher, mode and
 * padding:
 *
 * <ul>
 * <li>Wikipedia: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</li>
 * </ul>
 * "AES was announced by National Institute of Standards and Technology (NIST)
 * as U.S. FIPS PUB 197 (FIPS 197) on November 26, 2001 after a 5-year
 * standardization process in which fifteen competing designs were presented and
 * evaluated before Rijndael was selected as the most suitable (see Advanced
 * Encryption Standard process for more details). It became effective as a
 * Federal government standard on May 26, 2002 after approval by the Secretary
 * of Commerce. It is available in many different encryption packages. AES is
 * the first publicly accessible and open cipher approved by the NSA for top
 * secret information."
 *
 * <ul>
 * <li>Beginning Cryptography with Java</li>
 * </ul>
 * "CTR has been standardised by NIST in SP 800-38a and RFC 3686"
 *
 * <ul>
 * <li>
 * http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html</li>
 * </ul>
 * "AES is about as standard as you can get, and has done a good job of
 * resisting cryptologic attacks over the past decade. Using CTR mode avoids the
 * weakness of ECB mode, the complex (and bug-prone) process of padding and
 * unpadding of partial blocks (or ciphertext stealing), and vastly reduces the
 * risk of side channel attacks thanks to the fact that the data being input to
 * AES is not sensitive."
 * <p>
 * NOTE: CTR mode is "malleable", so if there is a requirement to assure the
 * integrity of the data, on top of encrypting it, this blog recommends adding
 * an HMAC (Hash-based Message Authentication Code).
 *
 * <ul>
 * <li>http://www.javamex.com/tutorials/cryptography/initialisation_vector.shtml
 * </li>
 * </ul>
 * The initialisation vector used in this class is a random one which, according
 * to this site, provides about the same risk of collision as OFB. Given that a
 * relatively small number of items will be encrypted, as compared to a stream
 * of messages which may contain tens of thousands of messages, this makes is a
 * good choice.
 *
 * <ul>
 * <li>Wikipedia: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</li>
 * </ul>
 * U.S. Government announced ... "The design and strength of all key lengths of
 * the AES algorithm (i.e., 128, 192 and 256) are sufficient to protect
 * classified information up to the SECRET level. TOP SECRET information will
 * require use of either the 192 or 256 key lengths". This class has been
 * designed to use 128-bit keys as this does not require unlimited strength
 * encryption and still provides a level of protection equivalent to that used
 * by SECRET level information. Since we are not transmitting these data over
 * the Internet, this seems a reasonable level of protection. It is not clear at
 * the time of writing what the performance impact of using longer keys will be
 * in practice, so this is not a factor in selection of the key size.
 *
 * @author David Carboni
 */
public class Crypto {

    /**
     * The name of the cipher algorithm to use for symmetric cryptographic
     * operations.
     */
    public static final String CIPHER_ALGORITHM = "AES";
    /**
     * The name of the cipher mode to use for symmetric cryptographic
     * operations.
     */
    public static final String CIPHER_MODE = "CTR";
    /**
     * The name of the padding type to use for symmetric cryptographic
     * operations.
     */
    public static final String CIPHER_PADDING = "NoPadding";

    /**
     * The full name of the {@link Cipher} to use for cryptographic operations,
     * in a format suitable for passing to the JCE.
     */
    public static final String CIPHER_NAME = CIPHER_ALGORITHM + "/" + CIPHER_MODE + "/" + CIPHER_PADDING;

    /**
     * This method encrypts the given String, returning a base-64 encoded
     * String. Note that the base-64 String will be longer than the input String
     * due base-64 encoding, the inclusion of an initialisation vector and a
     * salt value for the key generated from the given password.
     * <p>
     * A fixed length database field can therefore hold less encrypted than
     * plain-text data.
     *
     * @param string   The input String.
     * @param password A password to use as the basis for generating an encryption
     *                 key. This method calls
     *                 {@link Keys#generateSecretKey(String, String)}
     * @return The encrypted String, base-64 encoded, or null if the given
     * String is null. An empty string can be encrypted, but a null one
     * cannot.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #decrypt(String, String)
     */
    public String encrypt(String string, String password) {

        // Basic null check.
        // An empty string can be encrypted:
        if (string == null) {
            return null;
        }

        Cipher cipher = getCipher();

        // Generate the encryption key:
        String salt = Generate.salt();
        SecretKey key = Keys.generateSecretKey(password, salt);

        // Convert the input Sting to a byte array:
        byte[] iv = Generate.byteArray(getIvSize(cipher));
        byte[] data = ByteArray.fromString(string);

        // Encrypt the data:
        byte[] result = encrypt(iv, data, key, cipher);

        // Prepend the salt and IV
        byte[] saltBytes = ByteArray.fromBase64(salt);
        result = ArrayUtils.addAll(saltBytes, ArrayUtils.addAll(iv, result));

        // Return as a String:
        return ByteArray.toBase64(result);
    }

    /**
     * This method encrypts the given String, returning a base-64 encoded
     * String. Note that the base-64 String will be longer than the input String
     * due base-64 encoding and the inclusion of an initialisation vector.
     * <p>
     * A fixed length database field can therefore hold less encrypted than
     * plain-text data.
     *
     * @param string The input String.
     * @param key    The key to be used to encrypt the String.
     * @return The encrypted String, base-64 encoded, or null if the given
     * String is null. An empty string can be encrypted, but a null one
     * cannot.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #decrypt(String, SecretKey)
     */
    public String encrypt(String string, SecretKey key) {

        // Basic null check.
        // An empty string can be encrypted:
        if (string == null) {
            return null;
        }

        Cipher cipher = getCipher();

        // Convert the input Sting to a byte array:
        byte[] iv = Generate.byteArray(getIvSize(cipher));
        byte[] data = ByteArray.fromString(string);

        // Encrypt the data:
        byte[] result = encrypt(iv, data, key, cipher);

        // Prepend the IV
        result = ArrayUtils.addAll(iv, result);

        // Return as a String:
        return ByteArray.toBase64(result);
    }

    /**
     * This method encrypts a byte array. This is useful if you have raw binary
     * data you need to encrypt.
     * <p>
     * To keep the interface simple, this method is marked as protected. The
     * intention is that, if you need to encrypt byte arrays, you can subclass
     * {@link Crypto} to expose this method.
     * <p>
     * This is the bread-and-butter of most encryption operations, but
     * ultimately is a less common application-level use-case, because binary
     * data is usually stream-based and the rest of the time it tends to be
     * Strings you need to deal with. This is why it isn't exposed by default.
     *
     * @param iv   The initialisation vector.
     * @param data The cleartext data.
     * @param key  The key to be used to encrypt the data.
     * @param cipher The {@link Cipher} instance to use.
     * @return The encrypted data, or null if the given byte array is null. An
     * empty array can be encrypted, but a null one cannot.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #decrypt(byte[], byte[], SecretKey, Cipher)
     */
    protected byte[] encrypt(byte[] iv, byte[] data, SecretKey key, Cipher cipher) {

        // Basic null check.
        // An empty array can be encrypted:
        if (iv == null || data == null) {
            return null;
        }

        // Validate the initialisation vector:
        if (iv.length != getIvSize(cipher)) {
            throw new IllegalArgumentException("The supplied initialisation vector is the wrong size. Expected " + getIvSize(cipher) + " bytes but got " + iv.length + " bytes.");
        }

        // Prepare a cipher instance:
        initCipher(cipher, Cipher.ENCRYPT_MODE, key, iv);

        // Encrypt the data:
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("Block-size exception when completing encryption.", e);
        } catch (BadPaddingException e) {
            throw new IllegalStateException("Padding error detected when completing encryption.", e);
        }
    }

    /**
     * This method decrypts the given String and returns the plain text.
     *
     * @param encrypted The encrypted String, base-64 encoded, as returned by
     *                  {@link #encrypt(String, SecretKey)}.
     * @param password  The password used for encryption. This will be used to
     *                  generate the correct key by calling
     *                  {@link Keys#generateSecretKey(String, String)}
     * @return The decrypted String, or null if the encrypted String is null.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #encrypt(String, String)
     */
    public String decrypt(String encrypted, String password) {

        // Basic null/empty check.
        // An empty string can be encrypted, but not decrypted:
        if (StringUtils.isEmpty(encrypted)) {
            return encrypted;
        }

        Cipher cipher = getCipher();

        // Convert to a byte array:
        byte[] bytes = ByteArray.fromBase64(encrypted);

        // Validate the size of the encrypted data:
        if (bytes.length < Generate.SALT_BYTES + getIvSize(cipher)) {
            throw new IllegalArgumentException("Are you sure this is encrypted data? Byte length (" + bytes.length
                    + ") is shorter than a salt plus initialisation vector value.");
        }

        // Separate the salt and initialisation vector from the data:
        byte[] salt = ArrayUtils.subarray(bytes, 0, Generate.SALT_BYTES);
        byte[] iv = ArrayUtils.subarray(bytes, Generate.SALT_BYTES, Generate.SALT_BYTES + getIvSize(cipher));
        byte[] data = ArrayUtils.subarray(bytes, Generate.SALT_BYTES + getIvSize(cipher), bytes.length);

        // Generate the encryption key:
        SecretKey key = Keys.generateSecretKey(password, ByteArray.toBase64(salt));

        // Decrypt the data:
        byte[] result = decrypt(iv, data, key, cipher);

        // Return as a String:
        return ByteArray.toString(result);
    }

    /**
     * This method decrypts the given String and returns the plain text.
     *
     * @param encrypted The encrypted String, base-64 encoded, as returned by
     *                  {@link #encrypt(String, SecretKey)}.
     * @param key       The key to be used for decryption.
     * @return The decrypted String, or null if the encrypted String is null.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #encrypt(String, SecretKey)
     */
    public String decrypt(String encrypted, SecretKey key) {

        // Basic null/empty check.
        // An empty string can be encrypted, but not decrypted:
        if (StringUtils.isEmpty(encrypted)) {
            return encrypted;
        }

        Cipher cipher = getCipher();

        // Separate the initialisation vector from the data:
        byte[] bytes = ByteArray.fromBase64(encrypted);
        byte[] iv = ArrayUtils.subarray(bytes, 0, getIvSize(cipher));
        byte[] data = ArrayUtils.subarray(bytes, getIvSize(cipher), bytes.length);

        // Decrypt the data:
        byte[] result = decrypt(iv, data, key, cipher);

        // Return as a String:
        return ByteArray.toString(result);
    }

    /**
     * This method decrypts the given bytes and returns the plain text. This is
     * useful if you have raw binary data you need to decrypt.
     * <p>
     * To keep the interface simple, this method is marked as protected. The
     * intention is that, if you need to encrypt byte arrays, you can subclass
     * {@link Crypto} to expose this method.
     * <p>
     * This is the bread-and-butter of most encryption operations, but
     * ultimately is a less common application-level use-case, because binary
     * data is usually stream-based and the rest of the time it tends to be
     * Strings you need to deal with. This is why it isn't exposed by default.
     *
     * @param iv   The initialisation vector.
     * @param data The encrypted data.
     * @param key  The key to be used for decryption.
     * @return The decrypted String, or null if the encrypted String is null.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #encrypt(byte[], byte[], SecretKey, Cipher)
     */
    protected byte[] decrypt(byte[] iv, byte[] data, SecretKey key, Cipher cipher) {

        // Basic null/empty check.
        // An empty array can be encrypted, but not decrypted
        // - it must at least contain an initialisation vector:
        if (iv == null || data == null) {
            return null;
        }

        // Validate the initialisation vector:
        if (iv.length != getIvSize(cipher)) {
            throw new IllegalArgumentException("The supplied initialisation vector is the wrong size. Expected " + getIvSize(cipher) + " bytes but got " + iv.length + " bytes.");
        }

        // Prepare a cipher instance with the IV:
        initCipher(cipher, Cipher.DECRYPT_MODE, key, iv);

        // Decrypt the data:
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("Block-size exception when completing byte decryption.", e);
        } catch (BadPaddingException e) {
            throw new IllegalStateException("Padding error detected when completing byte decryption.", e);
        }
    }

    /**
     * This method wraps the destination {@link OutputStream} with a
     * {@link CipherOutputStream}.
     * <p>
     * Typical usage is when you have an InputStream for a source of unencrypted
     * data, such as a user-uploaded file, and an OutputStream to write the
     * input to disk. You would call this method to wrap the OutputStream and
     * use the returned {@link CipherOutputStream} instead to write the data to,
     * so that it is encrypted as it is written to disk.
     * <p>
     * Note that this method writes a salt value and an initialisation vector to
     * the destination OutputStream, so the destination parameter will have some
     * bytes written to it before this method returns. These bytes are necessary
     * for initialising encryption and a corresponding call to
     * {@link #decrypt(InputStream, String)} will read and filter them out from
     * the underlying InputStream before returning it.
     *
     * @param destination The output stream to be wrapped with a
     *                    {@link CipherOutputStream}.
     * @param password    The password to be used to generate a key to encrypt data
     *                    written to the returned {@link CipherOutputStream}.
     * @return A {@link CipherOutputStream}, which wraps the given
     * {@link OutputStream}.
     * @throws IOException              If an error occurs in writing the initialisation vector to
     *                                  the destination stream.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #decrypt(InputStream, String)
     */
    public OutputStream encrypt(OutputStream destination, String password) throws IOException {

        // Basic null check.
        // An empty stream can be encrypted:
        if (destination == null) {
            return null;
        }

        String salt = Generate.salt();
        SecretKey key = Keys.generateSecretKey(password, salt);

        // The key generation salt can be stored unencrypted at the start of the
        // stream:
        destination.write(ByteArray.fromBase64(salt));

        // Return the initialised stream:
        return encrypt(destination, key);
    }

    /**
     * This method wraps the destination {@link OutputStream} with a
     * {@link CipherOutputStream}.
     * <p>
     * Typical usage is when you have an InputStream for a source of unencrypted
     * data, such as a user-uploaded file, and an OutputStream to write the
     * input to disk. You would call this method to wrap the OutputStream and
     * use the returned {@link CipherOutputStream} instead to write the data to,
     * so that it is encrypted as it is written to disk.
     * <p>
     * Note that this method writes an initialisation vector to the destination
     * OutputStream, so the destination parameter will have some bytes written
     * to it before this method returns. These bytes are necessary for initialising
     * encryption and a corresponding call to
     * {@link #decrypt(InputStream, SecretKey)} will read and filter them out
     * from the underlying InputStream before returning it.
     *
     * @param destination The output stream to be wrapped with a
     *                    {@link CipherOutputStream}.
     * @param key         The key to be used to encrypt data written to the returned
     *                    {@link CipherOutputStream}.
     * @return A {@link CipherOutputStream}, which wraps the given
     * {@link OutputStream}.
     * @throws IOException              If an error occurs in writing the initialisation vector to
     *                                  the destination stream.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #decrypt(InputStream, SecretKey)
     */
    public OutputStream encrypt(OutputStream destination, SecretKey key) throws IOException {

        // Basic null check.
        // An empty stream can be encrypted:
        if (destination == null) {
            return null;
        }

        Cipher cipher = getCipher();

        // Generate an initialisation vector:
        byte[] iv = Generate.byteArray(getIvSize(cipher));

        // Get a cipher instance and instantiate the CipherOutputStream:
        initCipher(cipher, Cipher.ENCRYPT_MODE, key, iv);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(destination, cipher);

        // The IV can be stored unencrypted at the start of the
        // stream:
        destination.write(iv);

        // Return the initialised stream:
        return cipherOutputStream;
    }

    /**
     * This method wraps the source {@link InputStream} with a
     * {@link CipherInputStream}.
     * <p>
     * Typical usage is when you have an InputStream for a source of encrypted
     * data on disk, and an OutputStream to send the file to an HTTP response.
     * You would call this method to wrap the InputStream and use the returned
     * {@link CipherInputStream} to read the data from instead so that it is
     * decrypted as it is read and can be written to the response unencrypted.
     * <p>
     * Note that this method reads and discards a salt value and the random
     * initialisation vector from the source InputStream, so the source
     * parameter will have some bytes read from it before this method returns.
     * These bytes are necessary for initialising decryption and the call to
     * {@link #encrypt(OutputStream, String)} will have added these to the start
     * of the underlying data automatically.
     *
     * @param source   The source {@link InputStream}, containing encrypted data.
     * @param password The password to be used for decryption.
     * @return A {@link CipherInputStream}, which wraps the given source stream
     * and will decrypt the data as they are read.
     * @throws IOException              If an error occurs in reading the initialisation vector from
     *                                  the source stream.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #encrypt(OutputStream, String)
     */
    public InputStream decrypt(InputStream source, String password) throws IOException {

        // Remove the initialisation vector from the start of the stream.
        // NB if the stream is empty, the read will return -1 and no harm will
        // be done.
        byte[] salt = new byte[Generate.SALT_BYTES];

        // THe key generation salt can be stored unencrypted at the start of the stream:
        source.read(salt);

        // Generate the key:
        SecretKey key = Keys.generateSecretKey(password, ByteArray.toBase64(salt));

        // Return the initialised stream:
        return decrypt(source, key);
    }

    /**
     * This method wraps the source {@link InputStream} with a
     * {@link CipherInputStream}.
     * <p>
     * Typical usage is when you have an InputStream for a source of encrypted
     * data on disk, and an OutputStream to send the file to an HTTP response.
     * You would call this method to wrap the InputStream and use the returned
     * {@link CipherInputStream} to read the data from instead so that it is
     * decrypted as it is read and can be written to the response unencrypted.
     * <p>
     * Note that this method reads and discards the random initialisation vector
     * from the source InputStream, so the source parameter will have some bytes
     * read from it before this method returns. These bytes are necessary for initialising
     * decryption and the call to {@link #encrypt(OutputStream, SecretKey)} will
     * have added these to the start of the underlying data automatically.
     *
     * @param source The source {@link InputStream}, containing encrypted data.
     * @param key    The key to be used for decryption.
     * @return A {@link CipherInputStream}, which wraps the given source stream
     * and will decrypt the data as they are read.
     * @throws IOException              If an error occurs in reading the initialisation vector from
     *                                  the source stream.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     * @see #encrypt(OutputStream, SecretKey)
     */
    public InputStream decrypt(InputStream source, SecretKey key) throws IOException {

        Cipher cipher = getCipher();

        // Remove the initialisation vector from the start of the stream.
        // NB if the stream is empty, the read will return -1 and no harm will
        // be done.
        byte[] iv = new byte[getIvSize(cipher)];

        // The IV can be stored unencrypted at the start of the stream:
        source.read(iv);

        // Get a cipher instance and create the cipherInputStream:
        initCipher(cipher, Cipher.DECRYPT_MODE, key, iv);
        CipherInputStream cipherInputStream = new CipherInputStream(source, cipher);

        // Return the initialised stream:
        return cipherInputStream;
    }

    /**
     * @return The initialization vector size, in bytes.
     * <p>
     * This is useful if you want to check whether the size of input
     * data is large enough to represent encrypted data.
     * <p>
     * Encrypted strings and streams will always start with and IV and
     * can only be decrypted if the input is at least this long.
     *
     * @param cipher The cipher instance to get the IV size for.
     */
    private int getIvSize(Cipher cipher) {
        return cipher.getBlockSize();
    }

    /**
     * @return A new {@link Cipher} instance.
     */
    private Cipher getCipher() {
        try {

            // Get a Cipher instance:
            return Cipher.getInstance(CIPHER_NAME);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm unavailable: " + CIPHER_NAME, e);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding method unavailable: " + CIPHER_NAME, e);
        }
    }

    /**
     * This method returns a {@link Cipher} instance, for
     * {@value #CIPHER_ALGORITHM} in {@value #CIPHER_MODE} mode, with padding
     * {@value #CIPHER_PADDING}.
     * <p>
     * It then initialises the {@link Cipher} in either
     * {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}), as specified
     * by the mode parameter, with the given {@link SecretKey}.
     *
     * @param mode One of {@link Cipher#ENCRYPT_MODE} or
     *             {@link Cipher#DECRYPT_MODE}).
     * @param key  The {@link SecretKey} to be used with the {@link Cipher}.
     * @param iv   The initialisation vector to use.
     * @throws IllegalArgumentException If the given key is not a valid {@value #CIPHER_ALGORITHM}
     *                                  key.
     */
    private void initCipher(Cipher cipher, int mode, SecretKey key, byte[] iv) {

        // Initialise the cipher:
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        try {
            cipher.init(mode, key, ivParameterSpec);
        } catch (InvalidKeyException e) {
            // This is likely to be an invalid key size, so explain what just happened and signpost how to fix it.
            String message;
            if (StringUtils.containsIgnoreCase(e.getMessage(), "illegal key size")) {
                message = "It looks like your JVM doesn't allow you to use strong 256-bit AES keys. " +
                        "You can ";
            } else {
                message = "Invalid key for " + CIPHER_NAME +
                        ". NB: If the root cause of this exception is an Illegal key size, " +
                        "you can ";
            }
            throw new IllegalArgumentException(message + "either use Keys.useStandardKeys() to limit key size to 128-bits, or install the " +
                    "'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files' " +
                    "in your JVM to use 256-bit keys.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(
                    "Invalid parameter passed to initialise cipher for encryption: zero IvParameterSpec containing "
                            + cipher.getBlockSize() + " bytes.", e);
        }
    }
}
