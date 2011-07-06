package org.workdocx.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.workdocx.cryptolite.SecurityProvider;

/**
 * This class provides an abstraction that provides simple asymmetric encryption to support the
 * cryptographic requirements of WorkDocx.
 * <p>
 * Simplicity and abstraction is provided by having this class specify the details of the cipher,
 * cipher mode, padding and initialisation vector handling. This hides the complexity involved in
 * selecting types and values for these and allows the caller to simply request encryption and
 * decryption operations.
 * <p>
 * If you need to change the value of any of the constants in this class, please refactor the old
 * ones to different names. This is so that <code>EncryptionVersion.VERSION1</code> will continue to
 * be valid.
 * 
 * @author David Carboni
 * 
 */
public class AsymmetricProcessor {

	/** The key size for asymmetric cryptographic operations. */
	public static final int KEY_SIZE = 128;

	/** The name of the cipher algorithm to use for asymmetric cryptographic operations. */
	public static final String ALGORITHM = "RSA";
	/** The name of the cipher mode to use for asymmetric cryptographic operations. */
	public static final String CIPHER_MODE = "None";
	/** The name of the padding type to use for asymmetric cryptographic operations. */
	public static final String PADDING = "OAEPWithSHA1AndMGF1Padding";

	/**
	 * The full name of the cipher to use for asymmetric cryptographic operations, suitable for
	 * passing to JCE factory methods.
	 */
	public static final String CIPHER_NAME = ALGORITHM + "/" + CIPHER_MODE + "/" + PADDING;

//
//	/**
//	 * This method encrypts the given String, returning a base-64 encoded String. Note that the
//	 * base-64 String will be longer than the input String by 30-40% for an 85 character String. An
//	 * 85-character database field can therefore only hold 60 characters of plaintext. See the
//	 * output of {@link Codec#main(String[])} for details.
//	 * 
//	 * @param string
//	 *            The input String.
//	 * @param key
//	 *            The key to be used to encrypt the String.
//	 * @return The encrypted String, base-64 encoded.
//	 * @throws CryptographyException
//	 *             If an error occurs in encrypting the String.
//	 */
//	public String encrypt(String string, SecretKey key) throws CryptographyException {
//
//		// Prepare input and output byte arrays:
//		byte[] input = Codec.toBytes(string);
//		byte[] cipherText = encrypt(input, key);
//		return Codec.encode(cipherText);
//	}
//
//	/**
//	 * This method decrypts the given base-64 encoded String and returns the plain text.
//	 * 
//	 * @param base64
//	 *            The encrypted String.
//	 * @param key
//	 *            The key to be used for decryption.
//	 * @return The plaintext String.
//	 * @throws CryptographyException
//	 *             If an error occurs in decrypting the String.
//	 */
//	public String decrypt(String base64, SecretKey key) throws CryptographyException {
//
//		// Prepare input and output byte arrays:
//		byte[] input = Codec.decode(base64);
//		byte[] plaintext = decrypt(input, key);
//		return Codec.toString(plaintext);
//	}
//
//	/**
//	 * This method wraps the destination {@link OutputStream} with a {@link CipherOutputStream}.
//	 * Typical usage is when you have an InputStream for a source of plain-text, such as a
//	 * user-uploaded file, and an OutputStream to write the file to disk. You would call this method
//	 * to wrap the OutputStream and use the returned OutputStream to write the plain-text to, so
//	 * that it is encrypted as it is written to disk. Note that this method writes an initialisation
//	 * vector to the destination OutputStream, so the destination parameter will have some bytes
//	 * written to it by the time this method returns. These bytes are necessary for decryption and a
//	 * corresponding call to {@link #decrypt(InputStream, SecretKey)} will read them from the
//	 * underlying InputStream before returning it.
//	 * 
//	 * @param destination
//	 *            The output stream to be wrapped with a {@link CipherOutputStream}.
//	 * @param key
//	 *            The key to be used to encrypt data written to the returned
//	 *            {@link CipherOutputStream}.
//	 * @return A {@link CipherOutputStream}, which wraps the given OutputStream.
//	 * @throws CryptographyException
//	 *             If an error occurs in initialising the cipher or in writing the random
//	 *             initialisation vector to the destination stream.
//	 */
//	public OutputStream encrypt(OutputStream destination, SecretKey key) throws CryptographyException {
//
//		// Get a cipher instance and instantiate the CipherOutputStream:
//		Cipher cipher = initialiseSymmetricCipher(Cipher.ENCRYPT_MODE, key);
//		CipherOutputStream cipherOutputStream = new CipherOutputStream(destination, cipher);
//
//		// Initialise the CipherOutputStream with a random initialisation vector:
//		byte[] iv = generateInitialisationVector(cipher.getBlockSize());
//		try {
//			cipherOutputStream.write(iv);
//		} catch (IOException e) {
//			throw new CryptographyException("Error initialising " + CipherOutputStream.class.getSimpleName()
//					+ ": Error writing initialisation vector.", e);
//		}
//
//		// Return the initialised stream:
//		return cipherOutputStream;
//	}
//
//	/**
//	 * This method wraps the source {@link InputStream} with a {@link CipherInputStream}. Typical
//	 * usage is when you have an InputStream for a source of cipher-text on disk, such as a file in
//	 * the WorkDocx file store, and an OutputStream to send the file to an HTTP response. You would
//	 * call this method to wrap the InputStream and use the returned InputStream to read the
//	 * plain-text so that it is decrypted and can be written to the response. Note that this method
//	 * reads and discards the random initialisation vector from the source InputStream, so the
//	 * source parameter will have some bytes read from it by the time this method returns. These
//	 * bytes are necessary for decryption and the call to {@link #encrypt(OutputStream, SecretKey)}
//	 * will have added these to the start of the underlying data.
//	 * 
//	 * @param source
//	 *            The source {@link InputStream}, containing the encrypted data.
//	 * @param key
//	 *            The key to be used for decryption.
//	 * @return A {@link CipherInputStream}, which wraps the given source stream and will decrypt the
//	 *         data as they are read.
//	 * @throws CryptographyException
//	 *             If an error occurs in initialising the cipher or in reading and discarding the
//	 *             prepended random initialisation vector.
//	 */
//	public InputStream decrypt(InputStream source, SecretKey key) throws CryptographyException {
//
//		// Get a cipher instance and create the cipherInputStream:
//		Cipher cipher = initialiseSymmetricCipher(Cipher.DECRYPT_MODE, key);
//		CipherInputStream cipherInputStream = new CipherInputStream(source, cipher);
//
//		// Remove the random initialisation vector from the start of the stream:
//		byte[] iv = new byte[cipher.getBlockSize()];
//		try {
//			cipherInputStream.read(iv);
//		} catch (IOException e) {
//			throw new CryptographyException("Error initialising " + CipherInputStream.class.getSimpleName()
//					+ ": Error reading initialisation vector.", e);
//		}
//
//		// Return the initialised stream:
//		return cipherInputStream;
//	}
//
//	/**
//	 * This method encrypts the given plaintext, returning a corresponding ciphertext.
//	 * 
//	 * @param input
//	 *            The plaintext.
//	 * @param key
//	 *            The key to be used to encrypt the String.
//	 * @return The corresponding encrypted byte array.
//	 * @throws CryptographyException
//	 *             If an error occurs in encrypting the plaintext.
//	 */
//	private byte[] encrypt(byte[] input, SecretKey key) throws CryptographyException {
//
//		// Prepare a cipher instance with a zero IV:
//		Cipher cipher = initialiseSymmetricCipher(Cipher.ENCRYPT_MODE, key);
//
//		// Encrypt the input, prepending with a random initialisation vector:
//		byte[] iv = generateInitialisationVector(cipher.getBlockSize());
//		byte[] cipherText = new byte[iv.length + input.length];
//		int cipherTextLength;
//		try {
//			// Process the iv to get us started:
//			cipherTextLength = cipher.update(iv, 0, iv.length, cipherText, 0);
//			// Now process the plaintext:
//			cipherTextLength = cipher.update(input, 0, input.length, cipherText, cipherTextLength);
//		} catch (ShortBufferException e) {
//			throw new CryptographyException("The output buffer is too short to hold the cipher-text.", e);
//		}
//		try {
//			cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
//		} catch (IllegalBlockSizeException e) {
//			throw new CryptographyException("Block-size exception when completing String encrypiton.", e);
//		} catch (ShortBufferException e) {
//			throw new CryptographyException("The output buffer is too short to hold the cipher-text.", e);
//		} catch (BadPaddingException e) {
//			throw new CryptographyException("Padding error detected when completing String encrypiton.", e);
//		}
//		return cipherText;
//	}
//
//	/**
//	 * This method decrypts the given byte array and returns the plain text as a byte array.
//	 * 
//	 * @param input
//	 *            The ciphertext.
//	 * @param key
//	 *            The key to be used for decryption.
//	 * @return The plaintext byte array.
//	 * @throws CryptographyException
//	 *             If an error occurs in decrypting the ciphertext.
//	 */
//	private byte[] decrypt(byte[] input, SecretKey key) throws CryptographyException {
//
//		// Prepare the output byte array:
//		byte[] cipherText = new byte[input.length];
//
//		// Prepare a cipher instance with a zero IV:
//		Cipher cipher = initialiseSymmetricCipher(Cipher.DECRYPT_MODE, key);
//
//		// Decrypt the input, noting the result will be prepended with the IV used during encryption:
//		int cipherTextLength;
//		try {
//			cipherTextLength = cipher.update(input, 0, input.length, cipherText, 0);
//		} catch (ShortBufferException e) {
//			throw new CryptographyException("The output buffer is too short to hold the cipher-text.", e);
//		}
//		try {
//			cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
//		} catch (IllegalBlockSizeException e) {
//			throw new CryptographyException("Block-size exception when completing String encrypiton.", e);
//		} catch (ShortBufferException e) {
//			throw new CryptographyException("The output buffer is too short to hold the cipher-text.", e);
//		} catch (BadPaddingException e) {
//			throw new CryptographyException("Padding error detected when completing String encrypiton.", e);
//		}
//		byte[] plaintext = ArrayUtils.subarray(cipherText, cipher.getBlockSize(), cipherText.length);
//		return plaintext;
//	}
//
//	/**
//	 * This method returns a random initialisation vector.
//	 * 
//	 * @param size
//	 *            The size of the initialisation vector in bytes. This should correspond to the
//	 *            block size of the cipher.
//	 * 
//	 * @return A byte array of the specified size, containing random bytes.
//	 */
//	private byte[] generateInitialisationVector(int size) {
//		byte[] bytes = new byte[size];
//		SecureRandom secureRandom = new SecureRandom();
//		secureRandom.nextBytes(bytes);
//		return bytes;
//	}

//	/**
//	 * This method tests the {@link #encrypt(String, SecretKey)} and
//	 * {@link #decrypt(String, SecretKey)} methods above.
//	 * 
//	 * @param args
//	 *            Not used.
//	 * @throws CryptographyException
//	 *             If an error occurs.
//	 * @throws IOException .
//	 */
//	public static void main(String[] args) throws CryptographyException, IOException {
//
//		Provider.installProvider();
//
//		doString();
//		System.out.println();
//		System.out.println("---");
//		System.out.println();
//		doFile();
//	}
//
//	/**
//	 * This method demonstrates encrypting and decrypting a String.
//	 * 
//	 * @throws CryptographyException
//	 *             If any encrypt/decrypt error occurs.
//	 */
//	private static void doString() throws CryptographyException {
//
//		SecretKey key = KeyFactory.newSymmetric();
//		SymmetricProcessor symmetricProcessor = new SymmetricProcessor();
//
//		String string = "The quick brown fox & jumped over the �azy dog.";
//
//		String encrypted = symmetricProcessor.encrypt(string, key);
//
//		String decrypted = symmetricProcessor.decrypt(encrypted, key);
//
//		System.out.println(string);
//		System.out.println(encrypted);
//		System.out.println(decrypted);
//	}
//
//	/**
//	 * This method demonstrates encrypting and decrypting a String.
//	 * 
//	 * @throws CryptographyException
//	 *             If any encrypt/decrypt error occurs.
//	 * @throws IOException
//	 *             If an IO error occurs in handling the files.
//	 */
//	private static void doFile() throws CryptographyException, IOException {
//
//		SecretKey key = KeyFactory.newSymmetric();
//		SymmetricProcessor symmetricProcessor = new SymmetricProcessor();
//
//		// Prepare files:
//		File plaintext = File.createTempFile("plaintext", "file");
//		File encrypted = File.createTempFile("encrypted", "file");
//		File decrypted = File.createTempFile("decrypted", "file");
//		plaintext.deleteOnExit();
//		encrypted.deleteOnExit();
//		decrypted.deleteOnExit();
//
//		// Write the plaintext to the file:
//		String data = "The quick brown fox & jumped over the �azy dog.";
//		FileUtils.writeStringToFile(plaintext, data, "UTF8");
//
//		// Encrypt the plaintext:
//
//		InputStream plaintextInput = new FileInputStream(plaintext);
//		;
//		OutputStream encryptedOutput = new FileOutputStream(encrypted);
//		try {
//			// Wrap the stream and read the data:
//			encryptedOutput = symmetricProcessor.encrypt(encryptedOutput, key);
//			int b;
//			while ((b = plaintextInput.read()) != -1) {
//				encryptedOutput.write(b);
//			}
//		} finally {
//			IOUtils.closeQuietly(plaintextInput);
//			IOUtils.closeQuietly(encryptedOutput);
//		}
//
//		// Decrypt the ciphertext:
//
//		InputStream encryptedInput = new FileInputStream(encrypted);
//		OutputStream decryptedOutput = new FileOutputStream(decrypted);
//		try {
//			// Wrap the stream and read the data:
//			encryptedInput = symmetricProcessor.decrypt(encryptedInput, key);
//			int b;
//			while ((b = encryptedInput.read()) != -1) {
//				decryptedOutput.write(b);
//			}
//		} finally {
//			IOUtils.closeQuietly(plaintextInput);
//			IOUtils.closeQuietly(encryptedOutput);
//		}
//
//		// Compare the files:
//		System.out.println("Plaintext:\t" + plaintext.getName() + " " + plaintext.length());
//		System.out.println("Ciphertext:\t" + encrypted.getName() + " " + encrypted.length());
//		System.out.println("Decrypted:\t" + decrypted.getName() + " " + decrypted.length());
//
//		// Check length:
//		if (plaintext.length() == 0) {
//			throw new CryptographyException("Plaintext did not contain any data", new Exception());
//		}
//		if (plaintext.length() != decrypted.length()) {
//			throw new CryptographyException("Plaintext and decrypted files are not the same length", new Exception());
//		}
//
//		// Prepare streams for comparison:
//		InputStream decryptedInput;
//		plaintextInput = new FileInputStream(plaintext);
//		encryptedInput = new FileInputStream(encrypted);
//		decryptedInput = new FileInputStream(decrypted);
//		ByteArrayOutputStream bPlaintext = new ByteArrayOutputStream();
//		ByteArrayOutputStream bEncrypted = new ByteArrayOutputStream();
//		ByteArrayOutputStream bDecrypted = new ByteArrayOutputStream();
//
//		// Check that things do and don't match as expected:
//		boolean plaintextSameAsDecrypted = true;
//		boolean plaintextSameAsEncrypted = false;
//		int p, e, d;
//
//		// Ensure we read all files, to the end of the longest file:
//		while (((p = plaintextInput.read()) != -1) | ((e = encryptedInput.read()) != -1)
//				| ((d = decryptedInput.read()) != -1)) {
//			plaintextSameAsDecrypted &= (p == d);
//			plaintextSameAsEncrypted &= (p == e);
//
//			// Store the bytes, if read, so that we can print them out later:
//			if (p != -1) {
//				bPlaintext.write(p);
//			}
//			if (e != -1) {
//				bEncrypted.write(e);
//			}
//			if (d != -1) {
//				bDecrypted.write(d);
//			}
//		}
//
//		// Print out results:
//		System.out.println("Plaintext:\t" + Util.toHex(bPlaintext.toByteArray()) + " "
//				+ bPlaintext.toByteArray().length);
//		System.out.println("Encrypted:\t" + Util.toHex(bEncrypted.toByteArray()) + " "
//				+ bEncrypted.toByteArray().length);
//		System.out.println("Decrypted:\t" + Util.toHex(bDecrypted.toByteArray()) + " "
//				+ bDecrypted.toByteArray().length);
//
//		if (!plaintextSameAsDecrypted || plaintextSameAsEncrypted) {
//			throw new CryptographyException("Crypto fail. Sorry.", new Exception());
//		}
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
	private Cipher getAsymmetricCipher() throws RuntimeException {
		try {
			return Cipher.getInstance(AsymmetricProcessor.CIPHER_NAME, SecurityProvider.getProviderName());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate algorithm for " + AsymmetricProcessor.CIPHER_NAME, e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate provider. Are the BouncyCastle libraries installed?", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Unable to locate padding method " + AsymmetricProcessor.PADDING, e);
		}
	}

	/**
	 * This method initialises a {@link Cipher} in the given mode, with the specified
	 * {@link SecretKey}. This method calls {@link #getAsymmetricCipher()} internally.
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
	public Cipher initialiseAsymmetricCipher(int mode, SecretKey key) throws RuntimeException {

		// Prepare a cipher instance with a zero IV:
		Cipher cipher = getAsymmetricCipher();
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
