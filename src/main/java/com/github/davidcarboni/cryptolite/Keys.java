package com.github.davidcarboni.cryptolite;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * This class generates cryptographic keys.
 * <p/>
 * The following key types are available:
 * <ul>
 * <li>Deterministic Symmetric {@value #SYMMETRIC_ALGORITHM} keys of length
 * {@value #symmetricKeySize}, based on a password</li>
 * <li>Random Symmetric {@value #SYMMETRIC_ALGORITHM} keys of length {@value #symmetricKeySize}</li>
 * <li>Asymmetric {@value #ASYMMETRIC_ALGORITHM} keys of length {@value #ASYMMETRIC_KEY_SIZE}</li>
 * </ul>
 * <em>Deterministic keys:</em> these are the easiest to manage as they don't need to be stored. So
 * long as you pass in the same password each time, the same key will be generated every time. The
 * drawback is that if you want to generate more than one key you'll need more than one password.
 * However, if you do only need one key, this approach can be ideal as you can use the user's
 * plaintext password to generate the key. Since you never store a user's plaintext password (see
 * {@link Password#hash(String)}) the key can only be regenerated using the correct password. Bear
 * in mind however that if the user changes (or resets) their password this will result in a
 * different key, so you'll need a plan for recovering data encrypted with the old key and
 * re-encrypting it with the new one.
 * <p/>
 * <em>Random keys:</em> these are simple to generate, but need to be stored because it's
 * effectively impossible to regenerate the key. To store a key you should use
 * {@link KeyWrapper#wrapSecretKey(SecretKey)}. This produces an encrypted version of the key which
 * can safely be stored in, for example, a database or properties file. The benefit of the
 * {@link KeyWrapper} approach is that when a user changes their password you'll only need to
 * re-encrypt the stored keys using a {@link KeyWrapper} initialised with the new password, rather
 * than have to re-encrypt all data encrypted with the key.
 * <p/>
 * In both cases when a user changes their password you will have the old and the new plaintext
 * passwords, meaning you can decrypt with the old an re-encrypt with the new. The difficulty comes
 * when you need to reset a password, because it's not possible to recover the old password. In this
 * case you either need a secondary password, such as a security question, or you need to be clear
 * that data cannot be recovered. Whatever your solution, remember that storing someone's password
 * in any recoverable form is a clear security no-no, so you'll need to put some thought into the
 * recovery process.
 *
 * @author David Carboni
 */
public class Keys {

    /**
     * The symmetric encryption algorithm: {@value #SYMMETRIC_ALGORITHM}.
     */
    public static final String SYMMETRIC_ALGORITHM = "AES";

    /**
     * By default, the JVM will only allow {@value #SYMMETRIC_ALGORITHM} up to
     * {@value #SYMMETRIC_KEY_SIZE_STANDARD} bit keys. This is the default value used by this class.
     */
    public static final int SYMMETRIC_KEY_SIZE_STANDARD = 128;

    /**
     * If the "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" are
     * correctly installed for your JVM, it's possible to use {@value #SYMMETRIC_KEY_SIZE_UNLIMITED}
     * bit keys. Pass this constant to the {@link #setSymmetricKeySize(int)} method to enable
     * unlimited-strength cryptography.
     */
    public static final int SYMMETRIC_KEY_SIZE_UNLIMITED = 256;

    /**
     * The algorithm to use to generate password-based secret keys:
     * {@value #SYMMETRIC_PASSWORD_ALGORITHM}.
     */
    public static final String SYMMETRIC_PASSWORD_ALGORITHM = "PBKDF2WithHmacSHA1";

    /**
     * The number of iterations to use for password-based key derivation:
     * {@value #SYMMETRIC_PASSWORD_ITERATIONS}.
     */
    public static final int SYMMETRIC_PASSWORD_ITERATIONS = 1024;

    /**
     * The asymmetric encryption algorithm: {@value #ASYMMETRIC_ALGORITHM}.
     */
    public static final String ASYMMETRIC_ALGORITHM = "RSA";

    /**
     * The key size for asymmetric keys: {@value #ASYMMETRIC_KEY_SIZE}.
     */
    public static final int ASYMMETRIC_KEY_SIZE = 3072;

    /**
     * The key size for symmetric keys. This defaults to {@value #SYMMETRIC_KEY_SIZE_STANDARD} bit,
     * but can be changed to {@value #SYMMETRIC_KEY_SIZE_UNLIMITED} bit by calling
     * {@link #setSymmetricKeySize(int)} with the constant {@link #SYMMETRIC_KEY_SIZE_UNLIMITED}.
     */
    private static int symmetricKeySize = SYMMETRIC_KEY_SIZE_STANDARD;

    /**
     * This method generates a new secret (or symmetric) key for the {@value #SYMMETRIC_ALGORITHM}
     * algorithm with a key size of {@value #symmetricKeySize} bits.
     *
     * @return A new, randomly generated {@link SecretKey}.
     */
    public static SecretKey newSecretKey() {

        return newSecretKey(symmetricKeySize);
    }

    /**
     * This method generates a new secret (or symmetric) key for the {@value #SYMMETRIC_ALGORITHM}
     * algorithm with a key size of {@value #symmetricKeySize} bits.
     *
     * @param symmetricKeySize The key size to use. One of {@link #SYMMETRIC_KEY_SIZE_STANDARD} or
     *                         {@link #SYMMETRIC_KEY_SIZE_UNLIMITED}.
     * @return A new, randomly generated {@link SecretKey}.
     */
    private static SecretKey newSecretKey(int symmetricKeySize) {

        // FYI, see the source of: org.bouncycastle.crypto.CipherKeyGenerator.generateKey()
        // AES keys are just random bytes from a strong source of randomness.

        // Get a key generator instance
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM, SecurityProvider.getProviderName());
            keyGenerator.init(symmetricKeySize, Random.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to locate algorithm " + SYMMETRIC_ALGORITHM, e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Unable to locate JCE provider. Are the BouncyCastle libraries installed?", e);
        }

        // Generate a key:
        SecretKey result = keyGenerator.generateKey();

        return result;
    }

    /**
     * This method generates a new secret (or symmetric) key for the {@value #SYMMETRIC_ALGORITHM}
     * algorithm, using the given password and salt values. Given the same password and salt, this
     * method will (re)generate the same key.
     * <p/>
     * Note that this method may or may not handle blank passwords. This seems to be related to the
     * implementation of the {@value #SYMMETRIC_PASSWORD_ALGORITHM} algorithm in different Java
     * and/or BouncyCastle provider versions.
     *
     * @param password The starting point to use in generating the key. This can be a password, or any
     *                 suitably secret string. It's worth noting that, if a user's plaintext password is
     *                 used, this makes key derivation secure, but means the key can never be recovered
     *                 if a user forgets their password. If a different value, such as a password hash is
     *                 used, this is not really secure, but does mean the key can be recovered if a user
     *                 forgets their password. It's a trade-off, right?
     * @param salt     A value for this parameter can be generated by calling
     *                 {@link Random#salt()}. You'll need to store the salt value (this is ok to
     *                 do because salt isn't particularly sensitive) and use the same salt each time in
     *                 order to always generate the same key. Using salt is good practice as it ensures
     *                 that keys generated from the same password will be different - i.e. if two users
     *                 use the password "password", having a salt value avoids the generated keys being
     *                 identical which, for example, might give away someone's password.
     * @return A deterministic {@link SecretKey}, defined by the given password and salt
     */
    public static SecretKey generateSecretKey(String password, String salt) {
        return generateSecretKey(password.toCharArray(), salt, symmetricKeySize);
    }

    /**
     * This method generates a new secret (or symmetric) key for the {@value #SYMMETRIC_ALGORITHM}
     * algorithm, using the given password and salt values. Given the same password and salt, this
     * method will (re)generate the same key.
     *
     * @param password The starting point to use in generating the key. This can be a password, or any
     *                 suitably secret string. It's worth noting that, if a user's plaintext password is
     *                 used, this makes key derivation secure, but means the key can never be recovered
     *                 if a user forgets their password. If a different value, such as a password hash is
     *                 used, this is not really secure, but does mean the key can be recovered if a user
     *                 forgets their password. It's a trade-off, right?
     * @param salt     A value for this parameter can be generated by calling
     *                 {@link Random#salt()}. You'll need to store the salt value (this is ok to
     *                 do because salt isn't particularly sensitive) and use the same salt each time in
     *                 order to always generate the same key. Using salt is good practice as it ensures
     *                 that keys generated from the same password will be different - i.e. if two users
     *                 use the password "password", having a salt value avoids the generated keys being
     *                 identical which, for example, might give away someone's password.
     * @param keySize  The size of key to generate. For encryption this should be
     *                 {@link #symmetricKeySize}. For password hashing this should be
     *                 {@link Password#HASH_SIZE}
     * @return A deterministic {@link SecretKey}, defined by the given password and salt
     */
    static SecretKey generateSecretKey(char[] password, String salt, int keySize) {

        // Get a SecretKeyFactory for ALGORITHM:
        SecretKeyFactory factory;
        try {
            // TODO: BouncyCastle only provides PBKDF2 in their JDK 1.6 releases, so try to use it, if available:
            factory = SecretKeyFactory.getInstance(SYMMETRIC_PASSWORD_ALGORITHM, SecurityProvider.getProviderName());
        } catch (NoSuchAlgorithmException e) {
            try {
                // TODO: If PBKDF2 is not available from BouncyCastle, try to use a default provider (Sun provides PBKDF2 in JDK 1.5):
                factory = SecretKeyFactory.getInstance(SYMMETRIC_PASSWORD_ALGORITHM);
            } catch (NoSuchAlgorithmException e1) {
                throw new RuntimeException("Unable to locate algorithm " + SYMMETRIC_PASSWORD_ALGORITHM, e1);
            }
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Unable to locate JCE provider. Are the BouncyCastle libraries installed?", e);
        }

        // Generate the key:
        byte[] saltBytes = ByteArray.fromBase64String(salt);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, saltBytes, SYMMETRIC_PASSWORD_ITERATIONS, keySize);
        SecretKey key;
        try {
            key = factory.generateSecret(pbeKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Error generating password-based key.", e);
        }

        // NB: At this point, key.getAlgorithm() returns SYMMETRIC_PASSWORD_ALGORITHM,
        // rather than SYMMETRIC_ALGORITHM, so create a new SecretKeySpec with the correct
        // Algorithm.
        // For an example of someone using this method, see:
        // http://stackoverflow.com/questions/2860943/suggestions-for-library-to-hash-passwords-in-java
        return new SecretKeySpec(key.getEncoded(), SYMMETRIC_ALGORITHM);
    }

    /**
     * This method generates a new public-private (or asymmetric) key pair, using the
     * {@value #ASYMMETRIC_ALGORITHM} algorithm and a key size of {@value #ASYMMETRIC_KEY_SIZE}
     * bits.
     * <p/>
     * BouncyCastle will automatically generate a "Chinese Remainder Theorem" or CRT key, which
     * makes using a symmetric encryption significantly faster.
     *
     * @return A new, randomly generated asymmetric {@link KeyPair}.
     */
    public static KeyPair newKeyPair() {

        // Construct a key generator
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM, SecurityProvider.getProviderName());
            keyPairGenerator.initialize(ASYMMETRIC_KEY_SIZE, Random.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to locate algorithm " + ASYMMETRIC_ALGORITHM, e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Unable to locate provider. Are the BouncyCastle libraries installed?", e);
        }

        // Generate a key:
        KeyPair result = keyPairGenerator.generateKeyPair();

        return result;
    }

    /**
     * @return the symmetricKeySize
     */
    public static int getSymmetricKeySize() {
        return symmetricKeySize;
    }

    /**
     * Sets the key size for symmetric keys. This defaults to {@value #SYMMETRIC_KEY_SIZE_STANDARD}
     * bit ( {@link #SYMMETRIC_KEY_SIZE_STANDARD}) but can be changed to
     * {@value #SYMMETRIC_KEY_SIZE_UNLIMITED} bit by setting this field using the
     * {@link #SYMMETRIC_KEY_SIZE_UNLIMITED} constant.
     * <p/>
     * Note that whilst it's possible to generate a {@value #SYMMETRIC_KEY_SIZE_UNLIMITED} bit key
     * in any environment, you will need the
     * "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" installed in
     * your JVM in order to use it. To test this, you can use the {@link #canUseStrongKeys()}
     * method.
     *
     * @param newSymmetricKeySize the symmetricKeySize to set
     */
    public static void setSymmetricKeySize(int newSymmetricKeySize) {
        Keys.symmetricKeySize = newSymmetricKeySize;
    }

    /**
     * Tests whether the
     * "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" are
     * correctly installed.
     *
     * @return If strong keys can be used, true, otherwise false.
     */
    public static boolean canUseStrongKeys() {
        try {
            int maxKeyLen = Cipher.getMaxAllowedKeyLength(Crypto.CIPHER_ALGORITHM);
            return maxKeyLen >= SYMMETRIC_KEY_SIZE_UNLIMITED;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to locate algorithm " + Crypto.CIPHER_ALGORITHM, e);
        }
    }
}
