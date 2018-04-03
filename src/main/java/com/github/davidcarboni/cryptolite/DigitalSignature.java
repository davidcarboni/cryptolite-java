package com.github.davidcarboni.cryptolite;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * This class provides a public-private key digital signature capability. The signature algorithm
 * used is {@value #ALGORITHM}.
 *
 * @author David Carboni
 */
public class DigitalSignature {

    /**
     * The digital signature algorithm to use: {@value #ALGORITHM}.
     */
    public static final String ALGORITHM = "SHA256withRSAandMGF1";

    private String algorithm;

    /**
     * The default constructor initialises the instance with the {@value #ALGORITHM} algorithm.
     */
    public DigitalSignature() {
        this(ALGORITHM);
    }

    /**
     * This constructor is protected so that, should you need a different algorithm (e.g. if you're
     * integrating with a system that uses different crypto settings) it is possible to create a
     * subclass with different settings.
     *
     * @param algorithm This should normally be {@value #ALGORITHM}.
     */
    protected DigitalSignature(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Generates a digital signature for the given string.
     *
     * @param content    The string to be digitally signed.
     * @param privateKey The {@link PrivateKey} with which the string is to be signed. This can be obtained
     *                   via {@link Keys#newKeyPair()}.
     * @return The signature as a base64-encoded string. If the content is null, null is returned.
     */
    public String sign(String content, PrivateKey privateKey) {

        if (content == null) {
            return null;
        }

        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        InputStream input = new ByteArrayInputStream(bytes);
        return sign(input, privateKey);
        // ByteArrayInputStream does not need to be closed.
    }

    /**
     * Generates a digital signature for the given {@link InputStream}.
     *
     * @param content    The input to be digitally signed.
     * @param privateKey The {@link PrivateKey} with which the input is to be signed. This can be obtained
     *                   via {@link Keys#newKeyPair()}.
     * @return The signature as a base64-encoded string. If the content is null, null is returned.
     */
    public String sign(InputStream content, PrivateKey privateKey) {

        if (content == null) {
            return null;
        }

        Signature signer = getSignature();
        try {
            signer.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Error initialising digital signature - invalid key", e);
        }

        try {

            // Read the content:
            int b;
            try {
                while ((b = content.read()) != -1) {
                    signer.update((byte) b);
                }
            } catch (IOException e) {
                throw new IllegalArgumentException("Error reading input for digital signature creation", e);
            }

            // Generate the signature:
            byte[] signatureBytes = signer.sign();
            return ByteArray.toBase64(signatureBytes);

        } catch (SignatureException e) {
            throw new IllegalStateException("Error generating digital signature", e);
        }
    }

    /**
     * Verifies whether the given content matches the given signature.
     *
     * @param content   The content to be verified.
     * @param publicKey The public key to use in the verification process.
     * @param signature The signature with which the content is to be verified. This can be obtained via
     *                  {@link Keys#newKeyPair()}.
     * @return If the content matches the given signature, using the given key, true.
     */
    public boolean verify(String content, PublicKey publicKey, String signature) {

        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);

        InputStream input = new ByteArrayInputStream(bytes);
        return verify(input, publicKey, signature);
        // ByteArrayInputStream does not need to be closed.
    }

    /**
     * @param input     The content for which the signature is to be verified.
     * @param publicKey The {@link PublicKey} corresponding to the {@link PrivateKey} that was used to
     *                  sign the content. This can be obtained via {@link Keys#newKeyPair()}.
     * @param signature The signature to be verified.
     * @return If the signature matches the input and key, true. Otherwise false.
     */
    public boolean verify(InputStream input, PublicKey publicKey, String signature) {

        byte[] signatureBytes = ByteArray.fromBase64(signature);

        Signature signer = getSignature();
        try {
            signer.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Error initialising digital signature - invalid key", e);
        }

        try {

            // Read the content:
            int b;
            try {
                while ((b = input.read()) != -1) {
                    signer.update((byte) b);
                }
            } catch (IOException e) {
                throw new IllegalArgumentException("Error reading input for digital signature verification", e);
            }

            // Verify the signature:
            return signer.verify(signatureBytes);

        } catch (SignatureException e) {
            throw new IllegalStateException("Error verifying digital signature", e);
        }

    }

    /**
     * @return A new {@link Signature} instance.
     */
    protected Signature getSignature() {

        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            if (SecurityProvider.addProvider()) {
                return getSignature();
            } else {
                throw new IllegalStateException("Algorithm unavailable: " + algorithm, e);
            }
        }
    }

}
