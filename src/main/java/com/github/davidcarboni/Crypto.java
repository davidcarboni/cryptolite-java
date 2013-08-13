package com.github.davidcarboni;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

/**
 * 
 * This class provides simple encryption and decryption of Strings and streams.
 * <p>
 * This class uses the {@value #CIPHER_ALGORITHM} algorithm in
 * {@value #CIPHER_MODE} mode. This hides the complexity involved in selecting
 * types and values for these and allows the caller to simply request encryption
 * and decryption operations.
 * <p>
 * Some effort has been invested in choosing these values so that they are
 * suitable for the needs of a web application:
 * <ul>
 * <li>AES cipher: NIST standard for the transmission of classified US
 * government data.</li>
 * <li>CTR cipher mode: NIST standard cipher mode.</li>
 * <li>No padding: the CTR cipher mode is a "streaming" mode and therefore does
 * not require padding.</li>
 * <li>Inline initialisation vector: this avoids the need to handle the IV as an
 * additional out-of-band parameter.</li>
 * </ul>
 * <p>
 * Notes on background information used in selecting the cipher, mode and
 * padding:
 * <p>
 * <ul>
 * <li>Wikipedia: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</li>
 * </ul>
 * "AES was announced by National Institute of Standards and Technology (NIST)
 * as U.S. FIPS PUB 197 (FIPS 197) on November 26, 2001 after a 5-year
 * standardization process in which fifteen competing designs were presented and
 * evaluated before Rijndael was selected as the most suitable (see Advanced
 * Encryption Standard process for more details). It became effective as a
 * Federal government standard on May 26, 2002 after approval by the Secretary
 * of Commerce. It is available in many different encryption packages. AES is
 * the first publicly accessible and open cipher approved by the NSA for top
 * secret information."
 * <p>
 * <ul>
 * <li>Beginning Cryptography with Java</li>
 * </ul>
 * "CTR has been standardised by NIST in SP 800-38a and RFC 3686"
 * <p>
 * <ul>
 * <li>
 * http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html</li>
 * </ul>
 * "AES is about as standard as you can get, and has done a good job of
 * resisting cryptologic attacks over the past decade. Using CTR mode avoids the
 * weakness of ECB mode, the complex (and bug-prone) process of padding and
 * unpadding of partial blocks (or ciphertext stealing), and vastly reduces the
 * risk of side channel attacks thanks to the fact that the data being input to
 * AES is not sensitive."
 * <p>
 * NOTE: CTR mode is "malleable", so if there is a requirement to assure the
 * integrity of the data, on top of encrypting it, this blog recommends adding
 * an HMAC (Hash-based Message Authentication Code).
 * <p>
 * <ul>
 * <li>http://www.javamex.com/tutorials/cryptography/initialisation_vector.shtml
 * </li>
 * </ul>
 * The initialisation vector used in this class is a random one which, according
 * to this site, provides about the same risk of collision as OFB. Given that a
 * relatively small number of items will be encrypted, as compared to a stream
 * of messages which may contain tens of thousands of messages, this makes is a
 * good choice.
 * <p>
 * <ul>
 * <li>Wikipedia: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard</li>
 * </ul>
 * U.S. Government announced ... "The design and strength of all key lengths of
 * the AES algorithm (i.e., 128, 192 and 256) are sufficient to protect
 * classified information up to the SECRET level. TOP SECRET information will
 * require use of either the 192 or 256 key lengths". This class has been
 * designed to use 128-bit keys as this does not require unlimited strength
 * encryption and still provides a level of protection equivalent to that used
 * by SECRET level information. Since we are not transmitting these data over
 * the Internet, this seems a reasonable level of protection. It is not clear at
 * the time of writing what the performance impact of using longer keys will be
 * in practice, so this is not a factor in selection of the key size.
 * <p>
 * 
 * @author David Carboni
 * 
 */
public class Crypto {

	/**
	 * The name of the cipher algorithm to use for symmetric cryptographic
	 * operations.
	 */
	public static final String CIPHER_ALGORITHM = "AES";
	/**
	 * The name of the cipher mode to use for symmetric cryptographic
	 * operations.
	 */
	public static final String CIPHER_MODE = "CTR";
	/**
	 * The name of the padding type to use for symmetric cryptographic
	 * operations.
	 */
	public static final String CIPHER_PADDING = "NoPadding";

	/**
	 * The full name of the {@link Cipher} to use for cryptographic operations,
	 * in a format suitable for passing to the JCE.
	 */
	public static final String CIPHER_NAME = CIPHER_ALGORITHM + "/"
			+ CIPHER_MODE + "/" + CIPHER_PADDING;

	/** The {@link Cipher} for this instance. */
	private final Cipher cipher;

	/**
	 * Initialises the instance by getting and caching a {@link Cipher} instance
	 * for {@value #CIPHER_NAME}.
	 */
	public Crypto() {
		this(CIPHER_NAME);
	}

	/**
	 * This constructor is protected so that, should you need a different
	 * algorithm (e.g. if you're integrating with a system that uses different
	 * crypto settings) it is possible to create a subclass with different
	 * settings.
	 * 
	 * @param cipherName
	 *            This should normally be {@value #CIPHER_NAME}.
	 */
	protected Crypto(String cipherName) {

		try {

			// Get a Cipher instance:
			cipher = Cipher.getInstance(cipherName,
					SecurityProvider.getProviderName());

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to locate algorithm for "
					+ cipherName, e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(
					"Unable to locate provider. Are the BouncyCastle libraries installed?",
					e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Unable to locate padding method for "
					+ cipherName, e);
		}
	}

	/**
	 * This method encrypts the given String, returning a base-64 encoded
	 * String. Note that the base-64 String will be longer than the input String
	 * due base-64 encoding, the inclusion of an initialisation vector and a
	 * salt value for the key generated from the given password.
	 * <p>
	 * A fixed length database field can therefore hold less encrypted than
	 * plain-text data.
	 * 
	 * @see #decrypt(String, String)
	 * 
	 * @param string
	 *            The input String.
	 * @param password
	 *            A password to use as the basis for generating an encryption
	 *            key. This method calls
	 *            {@link Keys#generateSecretKey(String, String)}
	 * @return The encrypted String, base-64 encoded, or null if the given
	 *         String is null. An empty string can be encrypted, but a null one
	 *         cannot.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public String encrypt(String string, String password)
			throws InvalidKeyException {

		// Basic null check.
		// An empty string can be encrypted:
		if (string == null) {
			return null;
		}

		String salt = Random.generateSalt();
		SecretKey key = Keys.generateSecretKey(password, salt);

		// Convert the input Sting to a byte array:
		byte[] bytes = Codec.toByteArray(string);

		// Encrypt the data:
		byte[] result = ArrayUtils.addAll(Codec.fromBase64String(salt),
				encrypt(bytes, key));

		// Return as a String:
		return Codec.toBase64String(result);
	}

	/**
	 * This method encrypts the given String, returning a base-64 encoded
	 * String. Note that the base-64 String will be longer than the input String
	 * due base-64 encoding and the inclusion of an initialisation vector.
	 * <p>
	 * A fixed length database field can therefore hold less encrypted than
	 * plain-text data.
	 * 
	 * @see #decrypt(String, SecretKey)
	 * 
	 * @param string
	 *            The input String.
	 * @param key
	 *            The key to be used to encrypt the String.
	 * @return The encrypted String, base-64 encoded, or null if the given
	 *         String is null. An empty string can be encrypted, but a null one
	 *         cannot.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public String encrypt(String string, SecretKey key)
			throws InvalidKeyException {

		// Basic null check.
		// An empty string can be encrypted:
		if (string == null) {
			return null;
		}

		// Convert the input Sting to a byte array:
		byte[] bytes = Codec.toByteArray(string);

		// Encrypt the data:
		byte[] result = encrypt(bytes, key);

		// Return as a String:
		return Codec.toBase64String(result);
	}

	/**
	 * This method encrypts a byte array. This is useful if you have raw binary
	 * data you need to encrypt.
	 * <p>
	 * To keep the interface simple, this method is marked as protected. The
	 * intention is that, if you need to encrypt byte arrays, you can subclass
	 * {@link Crypto} to expose this method.
	 * <p>
	 * This is the bread-and-butter of most encryption operations, but
	 * ultimately is a less common application-level use-case, because binary
	 * data is usually stream-based and the rest of the time it tends to be
	 * Strings you need to deal with. This is why it isn't exposed by default.
	 * 
	 * @see #decrypt(byte[], SecretKey)
	 * 
	 * @param bytes
	 *            The input data.
	 * @param key
	 *            The key to be used to encrypt the data.
	 * @return The encrypted data, or null if the given byte array is null. An
	 *         empty array can be encrypted, but a null one cannot.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	protected byte[] encrypt(byte[] bytes, SecretKey key)
			throws InvalidKeyException {

		// Basic null check.
		// An empty array can be encrypted:
		if (bytes == null) {
			return null;
		}

		// Generate an initialisation vector:
		byte[] iv = generateInitialisationVector();

		// Prepare a cipher instance:
		initCipher(Cipher.ENCRYPT_MODE, key, iv);

		// Encrypt the data:
		byte[] result;
		try {
			result = cipher.doFinal(bytes);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(
					"Block-size exception when completing encrypiton.", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException(
					"Padding error detected when completing encrypiton.", e);
		}

		// Concatenate the iv and the encrypted data:
		result = ArrayUtils.addAll(iv, result);

		return result;
	}

	/**
	 * This method decrypts the given String and returns the plain text.
	 * 
	 * @see #encrypt(String, SecretKey)
	 * 
	 * @param encrypted
	 *            The encrypted String, base-64 encoded, as returned by
	 *            {@link #encrypt(String, SecretKey)}.
	 * @param password
	 *            The password used for encryption. This will be used to
	 *            generate the correct key by calling
	 *            {@link Keys#generateSecretKey(String, String)}
	 * @return The decrypted String, or null if the encrypted String is null.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public String decrypt(String encrypted, String password)
			throws InvalidKeyException {

		// Basic null/empty check.
		// An empty string can be encrypted, but not decrypted:
		if (StringUtils.isEmpty(encrypted)) {
			return encrypted;
		}

		// Convert to a byte array:
		byte[] bytes = Codec.fromBase64String(encrypted);
		if (bytes.length < Random.SALT_BYTES) {
			throw new IllegalArgumentException(
					"Are you sure this is encrypted data? Byte length ("
							+ bytes.length + ") is shorter than a salt value.");
		}

		// Separate the salt from the data:
		byte[] salt = ArrayUtils.subarray(bytes, 0, Random.SALT_BYTES);
		byte[] data = ArrayUtils.subarray(bytes, Random.SALT_BYTES,
				bytes.length);

		SecretKey key = Keys.generateSecretKey(password,
				Codec.toBase64String(salt));

		return Codec.fromByteArray(decrypt(data, key));
	}

	/**
	 * This method decrypts the given String and returns the plain text.
	 * 
	 * @see #encrypt(String, SecretKey)
	 * 
	 * @param encrypted
	 *            The encrypted String, base-64 encoded, as returned by
	 *            {@link #encrypt(String, SecretKey)}.
	 * @param key
	 *            The key to be used for decryption.
	 * @return The decrypted String, or null if the encrypted String is null.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public String decrypt(String encrypted, SecretKey key)
			throws InvalidKeyException {

		// Basic null/empty check.
		// An empty string can be encrypted, but not decrypted:
		if (StringUtils.isEmpty(encrypted)) {
			return encrypted;
		}

		byte[] bytes = Codec.fromBase64String(encrypted);
		return Codec.fromByteArray(decrypt(bytes, key));
	}

	/**
	 * This method decrypts the given bytes and returns the plain text. This is
	 * useful if you have raw binary data you need to decrypt.
	 * <p>
	 * To keep the interface simple, this method is marked as protected. The
	 * intention is that, if you need to encrypt byte arrays, you can subclass
	 * {@link Crypto} to expose this method.
	 * <p>
	 * This is the bread-and-butter of most encryption operations, but
	 * ultimately is a less common application-level use-case, because binary
	 * data is usually stream-based and the rest of the time it tends to be
	 * Strings you need to deal with. This is why it isn't exposed by default.
	 * 
	 * @see #encrypt(byte[], SecretKey)
	 * 
	 * @param bytes
	 *            The encrypted data.
	 * @param key
	 *            The key to be used for decryption.
	 * @return The decrypted String, or null if the encrypted String is null.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	protected byte[] decrypt(byte[] bytes, SecretKey key)
			throws InvalidKeyException {

		// Basic null/empty check.
		// An empty array can be encrypted, but not decrypted
		// - it must at least contain an initialisation vector:
		if (bytes == null) {
			return null;
		}

		int ivSize = cipher.getBlockSize();
		if (bytes.length < ivSize) {
			throw new IllegalArgumentException(
					"Are you sure this is encrypted data? Byte length ("
							+ bytes.length
							+ ") is shorter than an initialisation vector.");
		}
		byte[] iv;
		byte[] data;

		// Separate the IV from the data:
		iv = ArrayUtils.subarray(bytes, 0, ivSize);
		data = ArrayUtils.subarray(bytes, ivSize, bytes.length);

		// Prepare a cipher instance with the IV:
		initCipher(Cipher.DECRYPT_MODE, key, iv);

		// Decrypt the data:
		byte[] result;
		try {
			result = cipher.doFinal(data);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(
					"Block-size exception when completing String encrypiton.",
					e);
		} catch (BadPaddingException e) {
			throw new RuntimeException(
					"Padding error detected when completing String encrypiton.",
					e);
		}

		return result;
	}

	/**
	 * This method wraps the destination {@link OutputStream} with a
	 * {@link CipherOutputStream}.
	 * <p>
	 * Typical usage is when you have an InputStream for a source of unencrypted
	 * data, such as a user-uploaded file, and an OutputStream to write the
	 * input to disk. You would call this method to wrap the OutputStream and
	 * use the returned {@link CipherOutputStream} instead to write the data to,
	 * so that it is encrypted as it is written to disk.
	 * <p>
	 * Note that this method writes a salt value and an initialisation vector to
	 * the destination OutputStream, so the destination parameter will have some
	 * bytes written to it before this method returns. These bytes are necessary
	 * for decryption and a corresponding call to
	 * {@link #decrypt(InputStream, String)} will read and filter them out from
	 * the underlying InputStream before returning it.
	 * 
	 * @see #decrypt(InputStream, String)
	 * 
	 * @param destination
	 *            The output stream to be wrapped with a
	 *            {@link CipherOutputStream}.
	 * @param password
	 *            The password to be used to generate a key to encrypt data
	 *            written to the returned {@link CipherOutputStream}.
	 * @return A {@link CipherOutputStream}, which wraps the given
	 *         {@link OutputStream}.
	 * @throws IOException
	 *             If an error occurs in writing the initialisation vector to
	 *             the destination stream.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public OutputStream encrypt(OutputStream destination, String password)
			throws IOException, InvalidKeyException {

		// Basic null check.
		// An empty stream can be encrypted:
		if (destination == null) {
			return null;
		}

		String salt = Random.generateSalt();
		SecretKey key = Keys.generateSecretKey(password, salt);

		// Correct use is to store the IV unencrypted at the start of the
		// stream:
		destination.write(Codec.fromBase64String(salt));

		// Return the initialised stream:
		return encrypt(destination, key);
	}

	/**
	 * This method wraps the destination {@link OutputStream} with a
	 * {@link CipherOutputStream}.
	 * <p>
	 * Typical usage is when you have an InputStream for a source of unencrypted
	 * data, such as a user-uploaded file, and an OutputStream to write the
	 * input to disk. You would call this method to wrap the OutputStream and
	 * use the returned {@link CipherOutputStream} instead to write the data to,
	 * so that it is encrypted as it is written to disk.
	 * <p>
	 * Note that this method writes an initialisation vector to the destination
	 * OutputStream, so the destination parameter will have some bytes written
	 * to it before this method returns. These bytes are necessary for
	 * decryption and a corresponding call to
	 * {@link #decrypt(InputStream, SecretKey)} will read and filter them out
	 * from the underlying InputStream before returning it.
	 * 
	 * @see #decrypt(InputStream, SecretKey)
	 * 
	 * @param destination
	 *            The output stream to be wrapped with a
	 *            {@link CipherOutputStream}.
	 * @param key
	 *            The key to be used to encrypt data written to the returned
	 *            {@link CipherOutputStream}.
	 * @return A {@link CipherOutputStream}, which wraps the given
	 *         {@link OutputStream}.
	 * @throws IOException
	 *             If an error occurs in writing the initialisation vector to
	 *             the destination stream.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public OutputStream encrypt(OutputStream destination, SecretKey key)
			throws IOException, InvalidKeyException {

		// Basic null check.
		// An empty stream can be encrypted:
		if (destination == null) {
			return null;
		}

		// Generate an initialisation vector:
		byte[] iv = generateInitialisationVector();

		// Get a cipher instance and instantiate the CipherOutputStream:
		initCipher(Cipher.ENCRYPT_MODE, key, iv);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(
				destination, cipher);

		// Correct use is to store the IV unencrypted at the start of the
		// stream:
		destination.write(iv);

		// Return the initialised stream:
		return cipherOutputStream;
	}

	/**
	 * This method wraps the source {@link InputStream} with a
	 * {@link CipherInputStream}.
	 * <p>
	 * Typical usage is when you have an InputStream for a source of encrypted
	 * data on disk, and an OutputStream to send the file to an HTTP response.
	 * You would call this method to wrap the InputStream and use the returned
	 * {@link CipherInputStream} to read the data from instead so that it is
	 * decrypted as it is read and can be written to the response unencrypted.
	 * <p>
	 * Note that this method reads and discards the random initialisation vector
	 * from the source InputStream, so the source parameter will have some bytes
	 * read from it before this method returns. These bytes are necessary for
	 * decryption and the call to {@link #encrypt(OutputStream, SecretKey)} will
	 * have added these to the start of the underlying data automatically.
	 * 
	 * @see #encrypt(OutputStream, SecretKey)
	 * 
	 * @param source
	 *            The source {@link InputStream}, containing encrypted data.
	 * @param key
	 *            The key to be used for decryption.
	 * @return A {@link CipherInputStream}, which wraps the given source stream
	 *         and will decrypt the data as they are read.
	 * @throws IOException
	 *             If an error occurs in reading the initialisation vector from
	 *             the source stream.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public InputStream encrypt(InputStream source, SecretKey key)
			throws IOException, InvalidKeyException {

		// Remove the initialisation vector from the start of the stream.
		// NB if the stream is empty, the read will return -1 and no harm will
		// be done.
		byte[] iv = new byte[cipher.getBlockSize()];

		// The IV is stored unencrypted at the start of the stream:
		source.read(iv);

		// Get a cipher instance and create the cipherInputStream:
		initCipher(Cipher.DECRYPT_MODE, key, iv);
		CipherInputStream cipherInputStream = new CipherInputStream(source,
				cipher);

		// Return the initialised stream:
		return cipherInputStream;
	}

	/**
	 * This method wraps the source {@link InputStream} with a
	 * {@link CipherInputStream}.
	 * <p>
	 * Typical usage is when you have an InputStream for a source of encrypted
	 * data on disk, and an OutputStream to send the file to an HTTP response.
	 * You would call this method to wrap the InputStream and use the returned
	 * {@link CipherInputStream} to read the data from instead so that it is
	 * decrypted as it is read and can be written to the response unencrypted.
	 * <p>
	 * Note that this method reads and discards a salt value and the random
	 * initialisation vector from the source InputStream, so the source
	 * parameter will have some bytes read from it before this method returns.
	 * These bytes are necessary for decryption and the call to
	 * {@link #encrypt(OutputStream, String)} will have added these to the start
	 * of the underlying data automatically.
	 * 
	 * @see #encrypt(OutputStream, String)
	 * 
	 * @param source
	 *            The source {@link InputStream}, containing encrypted data.
	 * @param password
	 *            The password to be used for decryption.
	 * @return A {@link CipherInputStream}, which wraps the given source stream
	 *         and will decrypt the data as they are read.
	 * @throws IOException
	 *             If an error occurs in reading the initialisation vector from
	 *             the source stream.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public InputStream decrypt(InputStream source, String password)
			throws IOException, InvalidKeyException {

		// Remove the initialisation vector from the start of the stream.
		// NB if the stream is empty, the read will return -1 and no harm will
		// be done.
		byte[] salt = new byte[Random.SALT_BYTES];

		// The IV is stored unencrypted at the start of the stream:
		source.read(salt);

		// Generate the key:
		SecretKey key = Keys.generateSecretKey(password,
				Codec.toBase64String(salt));

		// Return the initialised stream:
		return decrypt(source, key);
	}

	/**
	 * This method wraps the source {@link InputStream} with a
	 * {@link CipherInputStream}.
	 * <p>
	 * Typical usage is when you have an InputStream for a source of encrypted
	 * data on disk, and an OutputStream to send the file to an HTTP response.
	 * You would call this method to wrap the InputStream and use the returned
	 * {@link CipherInputStream} to read the data from instead so that it is
	 * decrypted as it is read and can be written to the response unencrypted.
	 * <p>
	 * Note that this method reads and discards the random initialisation vector
	 * from the source InputStream, so the source parameter will have some bytes
	 * read from it before this method returns. These bytes are necessary for
	 * decryption and the call to {@link #encrypt(OutputStream, SecretKey)} will
	 * have added these to the start of the underlying data automatically.
	 * 
	 * @see #encrypt(OutputStream, SecretKey)
	 * 
	 * @param source
	 *            The source {@link InputStream}, containing encrypted data.
	 * @param key
	 *            The key to be used for decryption.
	 * @return A {@link CipherInputStream}, which wraps the given source stream
	 *         and will decrypt the data as they are read.
	 * @throws IOException
	 *             If an error occurs in reading the initialisation vector from
	 *             the source stream.
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	public InputStream decrypt(InputStream source, SecretKey key)
			throws IOException, InvalidKeyException {

		// Remove the initialisation vector from the start of the stream.
		// NB if the stream is empty, the read will return -1 and no harm will
		// be done.
		byte[] iv = new byte[cipher.getBlockSize()];

		// The IV is stored unencrypted at the start of the stream:
		source.read(iv);

		// Get a cipher instance and create the cipherInputStream:
		initCipher(Cipher.DECRYPT_MODE, key, iv);
		CipherInputStream cipherInputStream = new CipherInputStream(source,
				cipher);

		// Return the initialised stream:
		return cipherInputStream;
	}

	/**
	 * This method generates a random initialisation vector. The length of the
	 * IV is determined by calling {@link Cipher#getBlockSize()} on
	 * {@link #cipher}.
	 * 
	 * @return A byte array, of a size corresponding to the block size of the
	 *         given {@link Cipher}, containing random bytes.
	 */
	byte[] generateInitialisationVector() {
		byte[] bytes = new byte[cipher.getBlockSize()];
		Random.getInstance().nextBytes(bytes);
		return bytes;
	}

	/**
	 * @return The initialization vector size, in bytes.
	 *         <p>
	 *         This is useful if you want to check whether the size of input
	 *         data is large enough to represent encrypted data.
	 *         <p>
	 *         Encrypted strings and streams will always start with and IV and
	 *         can only be decrypted if the input is at least this long.
	 */
	public int getIvSize() {
		return cipher.getBlockSize();
	}

	/**
	 * This method returns a {@link Cipher} instance, for
	 * {@value #CIPHER_ALGORITHM} in {@value #CIPHER_MODE} mode, with padding
	 * {@value #CIPHER_PADDING}.
	 * <p>
	 * It then initialises the {@link Cipher} in either
	 * {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}), as specified
	 * by the mode parameter, with the given {@link SecretKey}.
	 * 
	 * @param mode
	 *            One of {@link Cipher#ENCRYPT_MODE} or
	 *            {@link Cipher#DECRYPT_MODE}).
	 * @param key
	 *            The {@link SecretKey} to be used with the {@link Cipher}.
	 * @param iv
	 *            The initialisation vector to use.
	 * 
	 * @throws InvalidKeyException
	 *             If the given key is not a valid {@value #CIPHER_ALGORITHM}
	 *             key.
	 */
	private void initCipher(int mode, SecretKey key, byte[] iv)
			throws InvalidKeyException {

		try {

			// Initialise the cipher:
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			cipher.init(mode, key, ivParameterSpec);

		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(
					"Invalid parameter passed to initialise cipher for encryption: zero IvParameterSpec containing "
							+ cipher.getBlockSize() + " bytes.", e);
		}
	}
}
