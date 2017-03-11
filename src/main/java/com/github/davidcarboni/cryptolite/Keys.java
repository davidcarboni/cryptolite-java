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
import java.security.spec.InvalidKeySpecException;

/**
 * This class generates cryptographic keys.
 * <p>
 * The following key types are available:
 * <ul>
 * <li>Deterministic symmetric/secret 256-bit AES keys, based on a password</li>
 * <li>GenerateRandom symmetric/secret 256-bit AES keys</li>
 * <li>Asymmetric 3072-bit RSA key pairs</li>
 * </ul>
 * <p>
 * <em>Deterministic keys:</em> these are the easiest to manage as they don't need to be stored. So
 * long as you pass in the same password each time, the same key will be generated every time. The
 * drawback is that if you want to generate more than one key you'll need more than one password.
 * However, if you do only need one key, this approach can be ideal as you can use the user's
 * plaintext password to generate the key. Since you never store a user's plaintext password (see
 * {@link Password#hash(String)}) the key can only be regenerated using the correct password. Bear
 * in mind however that if the user changes (or resets) their password this will result in a
 * different key, so you'll need a plan for recovering data encrypted with the old key and
 * re-encrypting it with the new one.
 * <p>
 * <em>GenerateRandom keys:</em> these are simple to generate, but need to be stored because it's
 * effectively impossible to regenerate the key. To store a key you should use
 * {@link KeyWrapper#wrapSecretKey(SecretKey)}. This produces an encrypted version of the key which
 * can safely be stored in, for example, a database or configuration value. The benefit of the
 * {@link KeyWrapper} approach is that when a user changes their password you'll only need to
 * re-encrypt the stored keys using a {@link KeyWrapper} initialised with the new password, rather
 * than have to re-encrypt all data encrypted with the key.
 * <p>
 * In both cases when a user changes their password you will have the old and the new plaintext
 * passwords, meaning you can decrypt with the old an re-encrypt with the new. The difficulty comes
 * when you need to reset a password, because it's not possible to recover the old password. In this
 * case you either need a secondary password, such as a security question, or you need to be clear
 * that data cannot be recovered. Whatever your solution, remember that storing someone's password
 * in any recoverable form is not OK, so you'll need to put some thought into the recovery process.
 *
 * @author David Carboni
 */
public class Keys {

    /**
     * The symmetric key algorithm.
     */
    public static final String SYMMETRIC_ALGORITHM = "AES";

    /**
     * The key size for symmetric keys.
     * <p>
     * This defaults to 256-bit ("strong"), but can be changed to 128-bit ("standard")
     * by calling {@link #useStandardKeys()}.
     */
    public static int SYMMETRIC_KEY_SIZE = 256;

    /**
     * The algorithm to use to generate password-based secret keys.
     */
    public static final String SYMMETRIC_PASSWORD_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * The number of iterations to use for password-based key derivation.
     */
    public static final int SYMMETRIC_PASSWORD_ITERATIONS = 1024;

    /**
     * The asymmetric key algorithm.
     */
    public static final String ASYMMETRIC_ALGORITHM = "RSA";

    /**
     * The key size for asymmetric keys.
     */
    public static final int ASYMMETRIC_KEY_SIZE = 3072;

    /**
     * Generates a new secret (or symmetric) key for use with {@value #SYMMETRIC_ALGORITHM}.
     * <p>
     * The key size is determined by {@link #SYMMETRIC_KEY_SIZE}.
     *
     * @return A new, randomly generated secret key.
     */
    public static SecretKey newSecretKey() {

        // FYI, see the source of: org.bouncycastle.crypto.CipherKeyGenerator.generateKey()
        // AES keys are just random bytes from a strong source of randomness.

        // Get a key generator instance
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            try {
                if (SecurityProvider.addProvider()) {
                    keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
                } else keyGenerator = null;
            } catch (NoSuchAlgorithmException e1) {
                keyGenerator = null;
            }
            if (keyGenerator == null) {
                throw new IllegalStateException("Algorithm unavailable: " + SYMMETRIC_ALGORITHM, e);
            }
        }

        // Generate a key:
        keyGenerator.init(SYMMETRIC_KEY_SIZE, GenerateRandom.getInstance());
        return keyGenerator.generateKey();
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
     *                 {@link GenerateRandom#salt()}. You'll need to store the salt value (this is ok to
     *                 do because salt isn't particularly sensitive) and use the same salt each time in
     *                 order to always generate the same key. Using salt is good practice as it ensures
     *                 that keys generated from the same password will be different - i.e. if two users
     *                 use the same password, having a salt value avoids the generated keys being
     *                 identical which might give away someone's password.
     * @return A deterministic secret key, defined by the given password and salt
     */
    static SecretKey generateSecretKey(String password, String salt) {

        if (password == null) {
            return null;
        }

        // Get a SecretKeyFactory for ALGORITHM:
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance(SYMMETRIC_PASSWORD_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            if (SecurityProvider.addProvider()) {
                // Retry
                return generateSecretKey(password, salt);
            } else {
                throw new IllegalStateException("Algorithm unavailable: " + SYMMETRIC_PASSWORD_ALGORITHM, e);
            }
        }

        // Generate the key:
        byte[] saltBytes = ByteArray.fromBase64String(salt);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), saltBytes, SYMMETRIC_PASSWORD_ITERATIONS, SYMMETRIC_KEY_SIZE);
        SecretKey key;
        try {
            key = factory.generateSecret(pbeKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Error generating password-based key.", e);
        }

        // NB: At this point, key.getAlgorithm() returns SYMMETRIC_PASSWORD_ALGORITHM,
        // rather than SYMMETRIC_ALGORITHM, so create a new SecretKeySpec with the correct
        // Algorithm.
        // For an example of someone using this method, see:
        // http://stackoverflow.com/questions/2860943/suggestions-for-library-to-hash-passwords-in-java
        return new SecretKeySpec(key.getEncoded(), SYMMETRIC_ALGORITHM);
    }

    /**
     * Generates a new public-private (or asymmetric) key pair for use with {@value #ASYMMETRIC_ALGORITHM}.
     *
     * The key size will be {@value #ASYMMETRIC_KEY_SIZE} bits.
     *
     * BouncyCastle will automatically generate a "Chinese Remainder Theorem" or CRT key, which
     * makes using a symmetric encryption significantly faster.
     *
     * @return A new, randomly generated asymmetric key pair.
     */
    public static KeyPair newKeyPair() {

        // Construct a key generator
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
            keyPairGenerator.initialize(ASYMMETRIC_KEY_SIZE, GenerateRandom.getInstance());
        } catch (NoSuchAlgorithmException e) {
            if (SecurityProvider.addProvider()) {
                return newKeyPair();
            } else {
                throw new IllegalStateException("Algorithm unavailable: " + ASYMMETRIC_ALGORITHM, e);
            }
        }

        // Generate a key:
        KeyPair result = keyPairGenerator.generateKeyPair();

        return result;
    }

    /**
     * If the "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" is
     * correctly installed for your JVM, it's possible to use strong (256-bit) keys.
     * <p>
     * To test whether you can use strong keys, call the {@link #canUseStrongKeys()} method.
     */
    public static void useStrongKeys() {
        SYMMETRIC_KEY_SIZE = 256;
    }

    /**
     * By default, the JVM will only allow up to 128-bit AES keys ("standard").
     * <p>
     * If you don't have the "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" installed,
     * you'll get an error if you try to use a 256-bit key (even though it is possible to generate a 256-bit key).
     * <p>
     * To test whether you can use strong keys, call the {@link #canUseStrongKeys()} method.
     */
    public static void useStandardKeys() {
        SYMMETRIC_KEY_SIZE = 128;
    }

    /**
     * Tests whether the
     * "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files" is
     * correctly installed.
     *
     * @return If strong keys can be used, true, otherwise false.
     */
    public static boolean canUseStrongKeys() {
        try {
            int maxKeyLen = Cipher.getMaxAllowedKeyLength(Crypto.CIPHER_ALGORITHM);
            return maxKeyLen > 128;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm unavailable: " + Crypto.CIPHER_ALGORITHM, e);
        }
    }
}
