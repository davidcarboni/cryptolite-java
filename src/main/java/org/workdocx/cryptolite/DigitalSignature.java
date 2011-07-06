/**
 * 
 */
package org.workdocx.cryptolite;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * @author david
 * 
 */
public class DigitalSignature {

	/** The digital signature algorithm to use: {@value #ALGORITHM}. */
	public static final String ALGORITHM = "SHA256withRSAandMGF1";

	/**
	 * Generates a digital signature for the given string.
	 * 
	 * @param content
	 *            The string to be digitally signed.
	 * @param privateKey
	 *            The {@link PrivateKey} with which the string is to be signed. This can be obtained
	 *            via {@link Keys#newKeyPair()}.
	 * @return The signature as a base64-encoded string.
	 */
	public String sign(String content, PrivateKey privateKey) {

		try {
			byte[] bytes = content.getBytes(Codec.ENCODING);
			InputStream input = new ByteArrayInputStream(bytes);
			return sign(input, privateKey);
			// ByteArrayInputStream does not need to be closed.
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Unable to get bytes from sring as " + Codec.ENCODING, e);
		}
	}

	/**
	 * Generates a digital signature for the given {@link InputStream}.
	 * 
	 * @param content
	 *            The input to be digitally signed.
	 * @param privateKey
	 *            The {@link PrivateKey} with which the input is to be signed. This can be obtained
	 *            via {@link Keys#newKeyPair()}.
	 * @return The signature as a base64-encoded string.
	 */
	public String sign(InputStream content, PrivateKey privateKey) {

		Signature signer = getSignature();
		try {
			signer.initSign(privateKey, Random.getInstance());
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Error initialising digital signature - invalid key", e);
		}

		try {

			// Read the content:
			int b;
			try {
				while ((b = content.read()) != -1) {
					signer.update((byte) b);
				}
			} catch (IOException e) {
				throw new RuntimeException("Error reading input for digital signature creation", e);
			}

			// Generate the signature:
			byte[] signatureBytes = signer.sign();
			return Codec.toBase64String(signatureBytes);

		} catch (SignatureException e) {
			throw new RuntimeException("Error generating digital signature", e);
		}
	}

	/**
	 * Verifies whether the given content matches the given signature.
	 * 
	 * @param content
	 *            The content to be verified.
	 * @param publicKey
	 *            The public key to use in the verification process.
	 * @param signature
	 *            The signature with which the content is to be verified. This can be obtained via
	 *            {@link Keys#newKeyPair()}.
	 * @return If the content matches the given signature, using the given key, true.
	 */
	public boolean verify(String content, PublicKey publicKey, String signature) {

		byte[] bytes;
		try {
			bytes = content.getBytes(Codec.ENCODING);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Unable to get bytes from sring as " + Codec.ENCODING, e);
		}

		InputStream input = new ByteArrayInputStream(bytes);
		return verify(input, publicKey, signature);
		// ByteArrayInputStream does not need to be closed.
	}

	/**
	 * @param input
	 *            The content for which the signature is to be verified.
	 * @param publicKey
	 *            The {@link PublicKey} corresponding to the {@link PrivateKey} that was used to
	 *            sign the content. This can be obtained via {@link Keys#newKeyPair()}.
	 * @param signature
	 *            The signature to be verified.
	 * @return If the signature matches the input and key, true. Otherwise false.
	 */
	public boolean verify(InputStream input, PublicKey publicKey, String signature) {

		byte[] signatureBytes = Codec.fromBase64String(signature);

		Signature signer = getSignature();
		try {
			signer.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Error initialising digital signature - invalid key", e);
		}

		try {

			// Read the content:
			int b;
			try {
				while ((b = input.read()) != -1) {
					signer.update((byte) b);
				}
			} catch (IOException e) {
				throw new RuntimeException("Error reading input for digital signature verification", e);
			}

			// Verify the signature:
			return signer.verify(signatureBytes);

		} catch (SignatureException e) {
			throw new RuntimeException("Error verifying digital signature", e);
		}

	}

	/**
	 * @return A new {@link Signature} instance.
	 */
	private Signature getSignature() {

		try {
			return Signature.getInstance(ALGORITHM, SecurityProvider.getProviderName());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to find algorithm " + ALGORITHM + " for provider "
					+ SecurityProvider.getProviderName(), e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to find provider. Are the BouncyCastle libraries installed?", e);
		}
	}

}
