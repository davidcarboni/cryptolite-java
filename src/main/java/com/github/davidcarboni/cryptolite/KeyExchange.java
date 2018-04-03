package com.github.davidcarboni.cryptolite;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * This class provides for key exchange, using public-private key encryption (also known as
 * asymmetric encryption).
 * <p>
 * The algorithm used is {@value #CIPHER_ALGORITHM}, with padding {@link #CIPHER_PADDING}, giving a
 * {@link Cipher} name of {@link #CIPHER_NAME}.
 * <p>
 * This class allows you to encrypt a {@link SecretKey} so that it can be securely sent to another
 * user. This is done using the destination user's {@link PublicKey} so that the recipient can
 * decrypt it using their {@link PrivateKey}.
 * <p>
 * Public-private key cryptography is not suitable for bulk encryption of data, (such as text and
 * documents) so if you need to send encrypted data from one user to another, the process for this
 * is slightly different, using both public-private and secret key encryption. If you wish to do
 * this, you need to use something along the lines of the following:
 * <ul>
 * <li>Encrypt the data being transmitted with a {@link SecretKey}, using the {@link Crypto} class.</li>
 * <li>Encrypt the {@link SecretKey} using the destination user's {@link PublicKey} by calling
 * {@link KeyExchange#encryptKey(SecretKey, PublicKey)}.</li>
 * <li>Send the encrypted {@link SecretKey} to the destination user with the encrypted data.</li>
 * <li>Use the destination user's {@link PrivateKey} to decrypt the {@link SecretKey}, by calling
 * {@link KeyExchange#decryptKey(String, PrivateKey)}.</li>
 * <li>The destination user can then use the recovered {@link SecretKey} to decrypt the data, using
 * the {@link Crypto} class.</li>
 * </ul>
 * <p>
 * This solves the problem of securely exchanging a {@link SecretKey} so that two parties can use
 * the same key to encrypt and decrypt data. Another approach is to use "key agreement", but this is
 * currently beyond the scope of Cryptolite.
 *
 * @author David Carboni
 */
public class KeyExchange {

    /**
     * The name of the cipher algorithm to use for asymmetric cryptographic operations.
     */
    public static final String CIPHER_ALGORITHM = "RSA";
    /**
     * The name of the cipher mode to use for asymmetric cryptographic operations.
     */
    public static final String CIPHER_MODE = "None";
    /**
     * The name of the padding type to use for asymmetric cryptographic operations.
     */
    public static final String CIPHER_PADDING = "OAEPWithSHA256AndMGF1Padding";

    /**
     * The full name of the cipher to use for asymmetric cryptographic operations, suitable for
     * passing to JCE factory methods.
     */
    private static final String CIPHER_NAME = CIPHER_ALGORITHM + "/" + CIPHER_MODE + "/" + CIPHER_PADDING;

    /**
     * The {@link Cipher} for this instance.
     */
    private Cipher cipher;
    private String cipherName;

    /**
     * Initialises the instance with the recommended setting of {@value #CIPHER_NAME}.
     */
    public KeyExchange() {
        this(CIPHER_NAME);
    }

    /**
     * This constructor is protected so that, should you need a different algorithm (e.g. if you're
     * integrating with a system that uses different crypto settings) it is possible to create a
     * subclass with different settings.
     *
     * @param cipherName This should normally be {@value #CIPHER_NAME}.
     */
    protected KeyExchange(String cipherName) {
        this.cipherName = cipherName;
    }

    /**
     * This method encrypts the given {@link SecretKey} with the destination user's
     * {@link PublicKey} so that it can be safely sent to them.
     *
     * @param key                  The {@link SecretKey} to be encrypted.
     * @param destinationPublicKey The {@link PublicKey} of the user to whom you will be sending the
     *                             {@link SecretKey}. This can be obtained via {@link Keys#newKeyPair()}.
     * @return The encrypted key, as a base64-encoded String, suitable for passing to
     * {@link #decryptKey(String, PrivateKey)}.
     */
    public String encryptKey(SecretKey key, PublicKey destinationPublicKey) {

        // Basic null check
        if (key == null) {
            return null;
        }

        // Convert the input key to a byte array:
        byte[] bytes = key.getEncoded();

        // Encrypt the bytes:
        byte[] encrypted;
        try {
            Cipher cipher = getCipher(destinationPublicKey);
            encrypted = cipher.doFinal(bytes);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalArgumentException("Error encrypting SecretKey: " + IllegalBlockSizeException.class.getSimpleName(), e);
        } catch (BadPaddingException e) {
            throw new IllegalArgumentException("Error encrypting SecretKey: " + BadPaddingException.class.getSimpleName(), e);
        }

        return ByteArray.toBase64(encrypted);
    }

    /**
     * This method decrypts the given encrypted {@link SecretKey} using our {@link PrivateKey}.
     *
     * @param encryptedKey The encrypted key as a base64-encoded string, as returned by
     *                     {@link #encryptKey(SecretKey, PublicKey)}.
     * @param privateKey   The {@link PrivateKey} to be used to decrypt the encrypted key. This can be
     *                     obtained via {@link Keys#newKeyPair()}.
     * @return The decrypted {@link SecretKey}.
     */
    public SecretKey decryptKey(String encryptedKey, PrivateKey privateKey) {

        // Basic null check
        if (encryptedKey == null) {
            return null;
        }

        // Convert the encryptedKey key String back to a byte array:
        byte[] bytes = ByteArray.fromBase64(encryptedKey);

        // Decrypt the bytes:
        byte[] decrypted;
        try {
            Cipher cipher = getCipher(privateKey);
            decrypted = cipher.doFinal(bytes);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalArgumentException("Error encrypting SecretKey: " + IllegalBlockSizeException.class.getSimpleName(), e);
        } catch (BadPaddingException e) {
            throw new IllegalArgumentException("Error decrypting SecretKey", e);
        }

        // Reconstruct the key:
        return new SecretKeySpec(decrypted, Crypto.CIPHER_ALGORITHM);
    }

    /**
     * This method returns a {@link Cipher} instance, for {@value #CIPHER_ALGORITHM} in mode
     * {@value #CIPHER_MODE}, with padding {@value #CIPHER_PADDING}.
     * <p>
     * It then initialises it in {@link Cipher#ENCRYPT_MODE} with the given {@link PublicKey}.
     *
     * @param key The {@link PublicKey} to be used with the {@link Cipher}.
     * @return A lazily-instantiated, cached {@link Cipher} instance.
     */
    private Cipher getCipher(PublicKey key) {

        return getCipher(Cipher.ENCRYPT_MODE, key);
    }

    /**
     * This method returns a {@link Cipher} instance, for {@value #CIPHER_ALGORITHM} in mode
     * {@value #CIPHER_MODE}, with padding {@value #CIPHER_PADDING}.
     * <p>
     * It then initialises it in {@link Cipher#DECRYPT_MODE} with the given {@link PrivateKey}.
     *
     * @param key The {@link PrivateKey} to be used with the {@link Cipher}.
     * @return A lazily-instantiated, cached {@link Cipher} instance.
     */
    private Cipher getCipher(PrivateKey key) {

        return getCipher(Cipher.DECRYPT_MODE, key);
    }

    /**
     * This method returns a {@link Cipher} instance, for {@value #CIPHER_ALGORITHM} in mode
     * {@value #CIPHER_MODE}, with padding {@value #CIPHER_PADDING}.
     * <p>
     * It then initialises the {@link Cipher} in either {@link Cipher#ENCRYPT_MODE} or
     * {@link Cipher#DECRYPT_MODE}), as specified by the mode parameter, with the given
     * {@link SecretKey}.
     *
     * @param mode One of {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}).
     * @param key  Either a {@link PublicKey} or a {@link PrivateKey} to be used with the
     *             {@link Cipher}.
     * @return A lazily-instantiated, cached {@link Cipher} instance.
     */
    private Cipher getCipher(int mode, Key key) {

        if (cipher == null) {

            try {

                // Get a Cipher instance:
                cipher = Cipher.getInstance(cipherName);

            } catch (NoSuchAlgorithmException e) {
                if (SecurityProvider.addProvider()) {
                    cipher = getCipher(mode, key);
                } else {
                    throw new IllegalStateException("Algorithm unavailable: " + cipherName, e);
                }
            } catch (NoSuchPaddingException e) {
                throw new IllegalStateException("Padding method unavailable: " + cipherName, e);
            }
        }

        // Initialise the Cipher
        try {
            cipher.init(mode, key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Invalid key used to initialise cipher.", e);
        }

        return cipher;
    }
}
