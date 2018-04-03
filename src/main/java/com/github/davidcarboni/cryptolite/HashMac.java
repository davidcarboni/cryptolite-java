package com.github.davidcarboni.cryptolite;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Provides a simple way to generate a Hash MAC (HMAC) using {@value #ALGORITHM}.
 *
 * @author David Carboni
 */
public class HashMac {

    /**
     * The algorithm used for computing HMACs.
     */
    public static final String ALGORITHM = "HmacSHA256";

    private byte[] key;

    private String algorithm;

    /**
     * This constructor provides parity with PHP's
     * <code>hash_hmac("sha256", "message", "key")</code> function.
     *
     * @param key An arbitrary String to use as a key.
     */
    public HashMac(String key) {
        this(ByteArray.fromString(key), ALGORITHM);
    }

    /**
     * This constructor allows you to use a {@link SecretKey} to generate an HMAC.
     * <p>
     * NB The {@link SecretKey#getEncoded()} method of the key should return a suitable byte array.
     * This is the case for keys generated/unwrapped using Cryptolite.
     *
     * @param key An key, whose {@link SecretKey#getEncoded()} method will be called.
     */
    public HashMac(SecretKey key) {
        this(key.getEncoded(), ALGORITHM);
    }

    /**
     * This constructor is protected so that, should you need a different algorithm (e.g. if you're
     * integrating with a system that uses different crypto settings) it is possible to create a
     * subclass with different settings.
     *
     * @param key       A byte array to use as the key.
     * @param algorithm This should normally be {@value #ALGORITHM}.
     */
    protected HashMac(byte[] key, String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    /**
     * Computes an HMAC for the given message, using the key passed to the constructor.
     *
     * @param message The message.
     * @return The HMAC value for the message and key.
     */
    public String digest(String message) {

        try {
            Mac mac = Mac.getInstance(algorithm);
            SecretKeySpec macKey = new SecretKeySpec(key, algorithm);
            mac.init(macKey);
            byte[] digest = mac.doFinal(ByteArray.fromString(message));
            return ByteArray.toHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm unavailable: " + algorithm, e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Unable to construct key for " + algorithm
                    + ". Please check the value passed in when this class was initialised.", e);
        }
    }
}
