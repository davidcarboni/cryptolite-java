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
 * Generates cryptographic keys.
 *
 * <h2>Key types</h2>
 * <ul>
 * <li>Secret keys (either randomly generated or deterministic, based on a password).</li>
 * <li>Public-Private key pairs.</li>
 * </ul>
 *
 * <h2>How to use keys</h2>
 * <ul>
 * <li>Secret keys are used for encryption (see {@link Crypto}).
 * <li>Secret keys are also used to secure other secret keys and private keys (see {@link KeyWrapper})
 * <li>Public-Private keys are used for digital signatures (see {@link DigitalSignature}).
 * <li>Public-Private keys are also used for key exchange (see {@link KeyExchange}).
 * </ul>
 *
 * <h2>Managing encryption keys</h2>
 * <p>
 * A good applied cryptography design is all about how you manage secrets: keys and passwords.
 * <p>
 * Assuming you're using primitives correctly (that's what Cryptolite does for you)
 * then it'll be all about your key management design.
 * <p>
 * Here are some examples, based on using secret keys to encrypt user data,
 * to give you a primer on the things you'll want to consider when designing with encryption.
 * In these examples, we're choosing between random and deterministic (password-based) keys.
 *
 * <h2>Deterministic key design</h2>
 * Deterministic keys are the easiest to manage as you don't need to store the key itself.
 * Providing the password used to generate the key is properly managed and is available
 * when you need access to the key, the key can be reliably regenerated each time.
 * <p>
 * The drawback is that if you want to generate more than one key you'll need more than one password.
 * However, if you do only need one key, this approach can be ideal as you could use, say, the user's
 * plaintext password to generate the key. You never store a user's plaintext password (see
 * {@link Password#hash(String)}) so the right key can only be generated when the user logs in.
 * <p>
 * Bear in mind however that if the user changes (or resets) their password this will generate a
 * different key, so you'll need a plan for recovering data encrypted with the old key and
 * re-encrypting it with the new one.
 *
 * <h2>Random key design</h2>
 * Random keys are simple to generate, but need to be stored because there's no way
 * to regenerate the same key.
 * <p>
 * To store a key you can use {@link KeyWrapper#wrapSecretKey(SecretKey)}.
 * This encrypts the key which means it can be safely stored in, for example,
 * a database or configuration value.
 * <p>
 * The benefit of the {@link KeyWrapper} approach is that
 * when a user changes their password you'll only need to re-encrypt the stored keys using a new
 * {@link KeyWrapper} initialised with the new password, rather than have to re-encrypt all
 * data that was encrypted with a key generated based on the user's password
 * (as in a deterministic design).
 *
 * <h2>Password recovery and reset</h2>
 * In both designs, when a user changes their password you will have the old and the new plaintext
 * passwords, meaning you can decrypt with the old an re-encrypt with the new.
 * <p>
 * The difficulty comes when you need to reset a password, because it's not possible to recover
 * the old password, so you can't recover the encryption key either. In this case you'll either
 * need a backup way to recover the encryption key, or you'll need to be clear that data cannot
 * be recovered at all.
 * <p>
 * Whatever your solution, remember that storing someone's password in any recoverable form is not OK,
 * so you'll need to put some thought into the recovery process.
 *
 * @author David Carboni
 */
public class Keys {

    // Please treat the following values as constants.
    // They are implemented as variables just in case you do need to alter them.
    // These are the settings that provide "right" cryptography so you'll need to
    // know what you're doing if you want to alter them.

    /**
     * The secret key algorithm.
     */
    public static final String SYMMETRIC_ALGORITHM = "AES";

    /**
     * The key size for secret keys.
     * <p>
     * This defaults to 256-bit ("strong"), but can be changed to 128-bit ("standard")
     * by calling {@link #useStandardKeys()} if your JVM does not have the
     * 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files' installed.
     * @see Crypto#initCipher(int, SecretKey, byte[])
     */
    public static int SYMMETRIC_KEY_SIZE = 256;

    /**
     * The algorithm to use to generate password-based secret keys.
     */
    public static final String SYMMETRIC_PASSWORD_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * The number of iteration rounds to use for password-based secret keys.
     */
    public static final int SYMMETRIC_PASSWORD_ITERATIONS = 1024;

    /**
     * The public-private key pair algorithm.
     */
    public static final String ASYMMETRIC_ALGORITHM = "RSA";

    /**
     * The key size for public-private key pairs.
     */
    public static final int ASYMMETRIC_KEY_SIZE = 4096;

    /**
     * Generates a new secret (also known as symmetric) key for use with {@value #SYMMETRIC_ALGORITHM}.
     * <p>
     * The key size is determined by {@link #SYMMETRIC_KEY_SIZE}.
     *
     * @return A new, randomly generated secret key.
     */
    public static SecretKey newSecretKey() {

        // FYI: AES keys are just random bytes from a strong source of randomness.

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
        keyGenerator.init(SYMMETRIC_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    /**
     * Generates a new secret (or symmetric) key for use with AES using the given password and salt values.
     *
     * Given the same password and salt, this method will always (re)generate the same key.
     *
     * @param password The starting point to use in generating the key. This can be a password, or any
     *                 suitably secret string. It's worth noting that, if a user's plaintext password is
     *                 used, this makes key derivation secure, but means the key can never be recovered
     *                 if a user forgets their password. If a different value, such as a password hash is
     *                 used, this is not really secure, but does mean the key can be recovered if a user
     *                 forgets their password. It's all about risk, right?
     * @param salt     A value for this parameter can be generated by calling
     *                 {@link Generate#salt()}. You'll need to store the salt value (this is ok to
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

        // Get a SecretKeyFactory for ALGORITHM.
        // If PBKDF2WithHmacSHA256, add BouncyCastle and recurse to retry.
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
        byte[] saltBytes = ByteArray.fromBase64(salt);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), saltBytes, SYMMETRIC_PASSWORD_ITERATIONS, SYMMETRIC_KEY_SIZE);
        SecretKey key;
        try {
            key = factory.generateSecret(pbeKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Error generating password-based key.", e);
        }

        // NB: At this point, key.getAlgorithm() returns PBKDF2WithHmacSHA256,
        // rather than AES, so create a new SecretKeySpec with the correct
        // Algorithm.
        // For an example of someone using this method, see:
        // http://stackoverflow.com/questions/2860943/suggestions-for-library-to-hash-passwords-in-java
        return new SecretKeySpec(key.getEncoded(), SYMMETRIC_ALGORITHM);
    }

    /**
     * Generates a new public-private (or asymmetric) key pair for use with {@value #ASYMMETRIC_ALGORITHM}.
     * <p>
     * The key size will be {@value #ASYMMETRIC_KEY_SIZE} bits.
     * <p>
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
            keyPairGenerator.initialize(ASYMMETRIC_KEY_SIZE);
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
