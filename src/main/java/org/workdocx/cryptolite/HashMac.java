package org.workdocx.cryptolite;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides a simple way to generate a Hash MAC (HMAC) using {@value #ALGORITHM}.
 * 
 * @author David Carboni
 * 
 */
public class HashMac {

	/**
	 * The algorithm used for computing HMACs.
	 */
	public static final String ALGORITHM = "HmacSHA256";

	private byte[] key;

	/**
	 * This constructor provides parity with PHP's
	 * <code>hash_hmac("sha256", "message", "key")</code> function.
	 * 
	 * @param key
	 *            An arbitrary String to use as a key.
	 */
	public HashMac(String key) {
		this.key = Codec.toByteArray(key);
	}

	/**
	 * This constructor allows you to use a {@link SecretKey} to generate an HMAC.
	 * <p>
	 * NB The {@link SecretKey#getEncoded()} method of the key should return a suitable byte array.
	 * This is the case for keys generated/unwrapped using Cryptolite.
	 * 
	 * @param key
	 *            An arbitrary String to use as a key.
	 */
	public HashMac(SecretKey key) {
		this.key = key.getEncoded();
	}

	/**
	 * Computes an HMAC for the given message, using the key passed to the constructor.
	 * 
	 * @param message
	 *            The message.
	 * @return The HMAC value for the message and key.
	 */
	public String digest(String message) {

		try {
			Mac mac = Mac.getInstance(ALGORITHM);
			SecretKeySpec macKey = new SecretKeySpec(key, ALGORITHM);
			mac.init(macKey);
			byte[] digest = mac.doFinal(Codec.toByteArray(message));
			return Codec.toHexString(digest);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate algorithm for " + ALGORITHM, e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Unable to construct key for " + ALGORITHM
					+ ". Please check the value passed in when this class was initialised.", e);
		}
	}
}
