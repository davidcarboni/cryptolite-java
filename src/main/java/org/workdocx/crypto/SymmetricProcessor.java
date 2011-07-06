package org.workdocx.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.lang.ArrayUtils;
import org.workdocx.cryptolite.Codec;
import org.workdocx.cryptolite.Random;
import org.workdocx.cryptolite.SecurityProvider;

/**
 * If you need to change the value of any of the constants in this class, please refactor the old
 * ones to different names. This is so that <code>EncryptionVersion.VERSION1</code> will continue to
 * be valid.
 * <p>
 * This class provides an abstraction that provides simple encryption and decryption of Strings and
 * streams to support the cryptographic requirements of WorkDocx.
 * <p>
 * Simplicity and abstraction is provided by having this class specify the details of the cipher,
 * cipher mode, padding and initialisation vector handling. This hides the complexity involved in
 * selecting types and values for these and allows the caller to simply request encryption and
 * decryption operations.
 * <p>
 * Some effort has been invested in choosing these values so that they are suitable for the needs of
 * WorkDocx:
 * <ul>
 * <li>AES cipher: NIST standard for the transmission of classified US government data.</li>
 * <li>CTR cipher mode: NIST standard cipher mode.</li>
 * <li>No padding: the CTR cipher mode is a "streaming" mode and therefore does not require padding.
 * </li>
 * <li>Inline initialisation vector: this avoids the need to handle the IV as an additional
 * out-of-band parameter.</li>
 * </ul>
 * <p>
 * Notes on background information used in selectingthe cipher, mode and padding:
 * <p>
 * <ul>
 * <li>Wikipedia: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</li>
 * </ul>
 * "AES was announced by National Institute of Standards and Technology (NIST) as U.S. FIPS PUB 197
 * (FIPS 197) on November 26, 2001 after a 5-year standardization process in which fifteen competing
 * designs were presented and evaluated before Rijndael was selected as the most suitable (see
 * Advanced Encryption Standard process for more details). It became effective as a Federal
 * government standard on May 26, 2002 after approval by the Secretary of Commerce. It is available
 * in many different encryption packages. AES is the first publicly accessible and open cipher
 * approved by the NSA for top secret information."
 * <p>
 * <ul>
 * <li>Beginning Cryptography with Java</li>
 * </ul>
 * "CTR has been standardised by NIST in SP 800-38a and RFC 3686"
 * <p>
 * <ul>
 * <li>http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html</li>
 * </ul>
 * "AES is about as standard as you can get, and has done a good job of resisting cryptologic
 * attacks over the past decade. Using CTR mode avoids the weakness of ECB mode, the complex (and
 * bug-prone) process of padding and unpadding of partial blocks (or ciphertext stealing), and
 * vastly reduces the risk of side channel attacks thanks to the fact that the data being input to
 * AES is not sensitive."
 * <p>
 * NOTE: CTR mode is "malleable", so if there is a requirement to assure the integrity of the data,
 * on top of encrypting it, this blog recommends adding an HMAC (Hash-based Message Authentication
 * Code).
 * <p>
 * <ul>
 * <li>http://www.javamex.com/tutorials/cryptography/initialisation_vector.shtml</li>
 * </ul>
 * The initialisation vector used in this class is a random one which, according to this site,
 * provides about the same risk of collision as OFB. Given that a relatively small number of items
 * will be encrypted, as compared to a stream of messages which may contain tens of thousands of
 * messages, this makes is a good choice.
 * <p>
 * <ul>
 * <li>Wikipedia: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</li>
 * </ul>
 * U.S. Government announced ... "The design and strength of all key lengths of the AES algorithm
 * (i.e., 128, 192 and 256) are sufficient to protect classified information up to the SECRET level.
 * TOP SECRET information will require use of either the 192 or 256 key lengths". This class has
 * been designed to use 128-bit keys as this does not require unlimited strength encryption and
 * still provides a level of protection equivalent to that used by SECRET level information. Since
 * we are not transmitting these data over the Internet, this seems a reasonable level of
 * protection. It is not clear at the time of writing what the performance impact of using longer
 * keys will be in practice, so this is not a factor in selection of the key size.
 * <p>
 * 
 * @author David Carboni
 * 
 */
public class SymmetricProcessor {

	/** The key size for symmetric cryptographic operations. */
	public static final int KEY_SIZE = 128;

	/** The name of the cipher algorithm to use for symmetric cryptographic operations. */
	public static final String ALGORITHM = "AES";
	/** The name of the cipher mode to use for symmetric cryptographic operations. */
	public static final String CIPHER_MODE = "CTR";
	/** The name of the padding type to use for symmetric cryptographic operations. */
	public static final String PADDING = "NoPadding";

	/**
	 * The full name of the cipher to use for symmetric cryptographic operations, suitable for
	 * passing to JCE factory methods.
	 */
	public static final String CIPHER_NAME = ALGORITHM + "/" + CIPHER_MODE + "/" + PADDING;

	/**
	 * This method encrypts the given String, returning a base-64 encoded String. Note that the
	 * base-64 String will be longer than the input String by 30-40% for an 85 character String. An
	 * 85-character database field can therefore only hold 60 characters of plaintext. See the
	 * output of {@link Codec#main(String[])} for details.
	 * 
	 * @param string
	 *            The input String.
	 * @param key
	 *            The key to be used to encrypt the String.
	 * @return The encrypted String, base-64 encoded.
	 * @throws RuntimeException
	 *             If an error occurs in encrypting the String.
	 */
	public String encrypt(String string, SecretKey key) throws RuntimeException {

		if (string == null) {
			return null;
		}

		// Prepare input and output byte arrays:
		byte[] input = Codec.toByteArray(string);
		byte[] cipherText = encrypt(input, key);
		String base64 = Codec.toBase64String(cipherText);
		return base64;
	}

	/**
	 * This method decrypts the given base-64 encoded String and returns the plain text.
	 * 
	 * @param base64
	 *            The encrypted String.
	 * @param key
	 *            The key to be used for decryption.
	 * @return The plaintext String.
	 * @throws RuntimeException
	 *             If an error occurs in decrypting the String.
	 */
	public String decrypt(String base64, SecretKey key) throws RuntimeException {

		if (base64 == null) {
			return null;
		}

		// Prepare input and output byte arrays:
		byte[] input = Codec.fromBase64String(base64);
		byte[] plaintext = decrypt(input, key);
		String decrypted = Codec.fromByteArray(plaintext);
		return decrypted;
	}

	/**
	 * This method wraps the destination {@link OutputStream} with a {@link CipherOutputStream}.
	 * Typical usage is when you have an InputStream for a source of plain-text, such as a
	 * user-uploaded file, and an OutputStream to write the file to disk. You would call this method
	 * to wrap the OutputStream and use the returned OutputStream to write the plain-text to, so
	 * that it is encrypted as it is written to disk. Note that this method writes an initialisation
	 * vector to the destination OutputStream, so the destination parameter will have some bytes
	 * written to it by the time this method returns. These bytes are necessary for decryption and a
	 * corresponding call to {@link #decrypt(InputStream, SecretKey)} will read them from the
	 * underlying InputStream before returning it.
	 * 
	 * @param destination
	 *            The output stream to be wrapped with a {@link CipherOutputStream}.
	 * @param key
	 *            The key to be used to encrypt data written to the returned
	 *            {@link CipherOutputStream}.
	 * @return A {@link CipherOutputStream}, which wraps the given OutputStream.
	 * @throws RuntimeException
	 *             If an error occurs in initialising the cipher or in writing the random
	 *             initialisation vector to the destination stream.
	 */
	public OutputStream encrypt(OutputStream destination, SecretKey key) throws RuntimeException {

		// Get a cipher instance and instantiate the CipherOutputStream:
		Cipher cipher = initialiseSymmetricCipher(Cipher.ENCRYPT_MODE, key);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(destination, cipher);

		// Initialise the CipherOutputStream with a random initialisation vector:
		byte[] iv = generateInitialisationVector(cipher.getBlockSize());
		try {
			cipherOutputStream.write(iv);
		} catch (IOException e) {
			throw new RuntimeException("Error initialising " + CipherOutputStream.class.getSimpleName()
					+ ": Error writing initialisation vector.", e);
		}

		// Return the initialised stream:
		return cipherOutputStream;
	}

	/**
	 * This method wraps the source {@link InputStream} with a {@link CipherInputStream}. Typical
	 * usage is when you have an InputStream for a source of cipher-text on disk, such as a file in
	 * the WorkDocx file store, and an OutputStream to send the file to an HTTP response. You would
	 * call this method to wrap the InputStream and use the returned InputStream to read the
	 * plain-text so that it is decrypted and can be written to the response. Note that this method
	 * reads and discards the random initialisation vector from the source InputStream, so the
	 * source parameter will have some bytes read from it by the time this method returns. These
	 * bytes are necessary for decryption and the call to {@link #encrypt(OutputStream, SecretKey)}
	 * will have added these to the start of the underlying data.
	 * 
	 * @param source
	 *            The source {@link InputStream}, containing the encrypted data.
	 * @param key
	 *            The key to be used for decryption.
	 * @return A {@link CipherInputStream}, which wraps the given source stream and will decrypt the
	 *         data as they are read.
	 * @throws RuntimeException
	 *             If an error occurs in initialising the cipher or in reading and discarding the
	 *             prepended random initialisation vector.
	 */
	public InputStream decrypt(InputStream source, SecretKey key) throws RuntimeException {

		// Get a cipher instance and create the cipherInputStream:
		Cipher cipher = initialiseSymmetricCipher(Cipher.DECRYPT_MODE, key);
		CipherInputStream cipherInputStream = new CipherInputStream(source, cipher);

		// Remove the random initialisation vector from the start of the stream.
		// NB if the stream is empty, the read will return -1 and no harm will be done.
		byte[] iv = new byte[cipher.getBlockSize()];
		try {
			cipherInputStream.read(iv);
		} catch (IOException e) {
			throw new RuntimeException("Error initialising " + CipherInputStream.class.getSimpleName()
					+ ": Error reading initialisation vector.", e);
		}

		// Return the initialised stream:
		return cipherInputStream;
	}

	/**
	 * This method encrypts the given plaintext, returning a corresponding ciphertext.
	 * 
	 * @param input
	 *            The plaintext.
	 * @param key
	 *            The key to be used to encrypt the String.
	 * @return The corresponding encrypted byte array.
	 * @throws RuntimeException
	 *             If an error occurs in encrypting the plaintext.
	 */
	private byte[] encrypt(byte[] input, SecretKey key) throws RuntimeException {

		// Prepare a cipher instance with a zero IV:
		Cipher cipher = initialiseSymmetricCipher(Cipher.ENCRYPT_MODE, key);

		// Encrypt the input, prepending with a random initialisation vector:
		byte[] iv = generateInitialisationVector(cipher.getBlockSize());
		byte[] cipherText = new byte[iv.length + input.length];
		int cipherTextLength;
		try {
			// Process the iv to get us started:
			cipherTextLength = cipher.update(iv, 0, iv.length, cipherText, 0);
			// Now process the plaintext:
			cipherTextLength = cipher.update(input, 0, input.length, cipherText, cipherTextLength);
		} catch (ShortBufferException e) {
			throw new RuntimeException("The output buffer is too short to hold the cipher-text.", e);
		}
		try {
			cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Block-size exception when completing String encrypiton.", e);
		} catch (ShortBufferException e) {
			throw new RuntimeException("The output buffer is too short to hold the cipher-text.", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Padding error detected when completing String encrypiton.", e);
		}
		return cipherText;
	}

	/**
	 * This method decrypts the given byte array and returns the plain text as a byte array.
	 * 
	 * @param input
	 *            The ciphertext.
	 * @param key
	 *            The key to be used for decryption.
	 * @return The plaintext byte array.
	 * @throws RuntimeException
	 *             If an error occurs in decrypting the ciphertext.
	 */
	private byte[] decrypt(byte[] input, SecretKey key) throws RuntimeException {

		// Prepare the output byte array:
		byte[] cipherText = new byte[input.length];

		// Prepare a cipher instance with a zero IV:
		Cipher cipher = initialiseSymmetricCipher(Cipher.DECRYPT_MODE, key);

		// Decrypt the input, noting the result will be prepended with the IV used during encryption:
		int cipherTextLength;
		try {
			cipherTextLength = cipher.update(input, 0, input.length, cipherText, 0);
		} catch (ShortBufferException e) {
			throw new RuntimeException("The output buffer is too short to hold the cipher-text.", e);
		}
		try {
			cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Block-size exception when completing String encrypiton.", e);
		} catch (ShortBufferException e) {
			throw new RuntimeException("The output buffer is too short to hold the cipher-text.", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Padding error detected when completing String encrypiton.", e);
		}
		byte[] plaintext = ArrayUtils.subarray(cipherText, cipher.getBlockSize(), cipherText.length);
		return plaintext;
	}

	/**
	 * This method returns a random initialisation vector.
	 * 
	 * @param size
	 *            The size of the initialisation vector in bytes. This should correspond to the
	 *            block size of the cipher.
	 * 
	 * @return A byte array of the specified size, containing random bytes.
	 */
	private byte[] generateInitialisationVector(int size) {
		byte[] bytes = new byte[size];
		SecureRandom secureRandom = Random.getInstance();
		secureRandom.nextBytes(bytes);
		return bytes;
	}

//	public static void main(String[] args) {
//		SecureRandom random = new SecureRandom();
//		byte[] bytes = new byte[SymmetricProcessor.KEY_SIZE];
//		random.nextBytes(bytes);
//		for (byte b : bytes) {
//			System.out.print(b + ", ");
//		}
//		System.out.println();
//	}
	/**
	 * This method get a cipher instance, based on {@link #ALGORITHM}, {@link #CIPHER_MODE} and
	 * {@link #PADDING}: {@value #ALGORITHM}/{@value #CIPHER_MODE}/{@value #PADDING}. It also
	 * handles the various exceptions that can be thrown, wrapping them in a
	 * {@link RuntimeException} in order to simplify the checked exception list.
	 * <p>
	 * 
	 * @return A {@link Cipher} instance.
	 * @throws RuntimeException
	 *             If an error occurs in initialising the {@link Cipher}.
	 */
	Cipher getSymmetricCipher() throws RuntimeException {
		try {
			return Cipher.getInstance(SymmetricProcessor.CIPHER_NAME, SecurityProvider.getProviderName());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate algorithm for " + SymmetricProcessor.CIPHER_NAME, e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate provider. Are the BouncyCastle libraries installed?", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Unable to locate padding method " + SymmetricProcessor.PADDING, e);
		}
	}

	/**
	 * This method initialises a {@link Cipher} in the given mode, with the specified
	 * {@link SecretKey}. This method calls {@link #getSymmetricCipher()} internally.
	 * 
	 * @param mode
	 *            The cipher mode (e.g. {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
	 * @param key
	 *            The {@link SecretKey} to be used with the {@link Cipher}.
	 * @return An initialised {@link Cipher} instance. Specifically, the
	 *         {@link Cipher#init(int, java.security.Key, java.security.spec.AlgorithmParameterSpec)}
	 *         method will have been called.
	 * @throws RuntimeException
	 *             If an error occurs in generating or initialising the {@link Cipher}.
	 */
	public Cipher initialiseSymmetricCipher(int mode, SecretKey key) throws RuntimeException {

		// Prepare a cipher instance with a zero IV:
		Cipher cipher = getSymmetricCipher();
		IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[cipher.getBlockSize()]);
		try {
			cipher.init(mode, key, ivParameterSpec);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid key used to initialise cipher for encryption.", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(
					"Invalid parameter passed to initialiset cipher for encryption: zero IvParameterSpec containing "
							+ cipher.getBlockSize() + " bytes.", e);
		}
		return cipher;
	}
}
