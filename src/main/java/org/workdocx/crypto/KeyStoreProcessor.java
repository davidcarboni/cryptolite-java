package org.workdocx.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.workdocx.cryptolite.SecurityProvider;

/**
 * This class provides facilities for handling a user {@link KeyStore}.
 * <p>
 * If you need to change the value of any of the constants in this class, please refactor the old
 * ones to different names. This is so that <code>EncryptionVersion.VERSION1</code> will continue to
 * be valid.
 * 
 * @author David Carboni
 * 
 */
public class KeyStoreProcessor {

	/** The type of keystore to be used. */
	public static final String KEYSTORE_TYPE = "PKCS12";
	/** Certificate validity is 1000 years to make it effectively unlimited. */
	private static final long VALIDITY_PERIOD = 1000 * 60 * 60 * 24 * 365 * 1000;

	/**
	 * Creates a new {@link KeyStore}.
	 * 
	 * @return A new, initialised {@link KeyStore} instance.
	 * @throws RuntimeException
	 *             If an error occurs in creating the key store.
	 */
	public KeyStore create() throws RuntimeException {

		return initialiseStore(null, null);
	}

	/**
	 * Loads the given store.
	 * 
	 * @param source
	 *            The stream from which to load the store.
	 * @param password
	 *            The password for the store.
	 * @return The initialised {@link KeyStore}.
	 * @throws RuntimeException
	 *             If an error occurs in creating the key store.
	 */
	public KeyStore read(InputStream source, String password) throws RuntimeException {
		return initialiseStore(source, password);
	}

	/**
	 * Updates the given store.
	 * 
	 * @param target
	 *            The stream to which the store is to be saved.
	 * @param password
	 *            The password to use for protecting the store.
	 * @param keyStore
	 *            The {@link KeyStore} instance to be persisted.
	 * @throws RuntimeException
	 *             If an error occurs in saving the keystore.
	 */
	public void update(OutputStream target, String password, KeyStore keyStore) throws RuntimeException {
		try {
			keyStore.store(target, password.toCharArray());
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error saving key store.", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to save keystore - no such algorithm.", e);
		} catch (CertificateException e) {
			throw new RuntimeException("Unable to save keystore - certificate error.", e);
		} catch (IOException e) {
			throw new RuntimeException("Unable to save keystore - IO exception.", e);
		}
	}

	/**
	 * Initialises the given {@link KeyStore}.
	 * 
	 * @param source
	 *            The source stream for the store, may be null.
	 * @param password
	 *            The password for the store - may be null.
	 * @return An initialised {@link KeyStore} instance.
	 * @throws RuntimeException
	 *             If an error occurs in creating or initialising the store.
	 */
	KeyStore initialiseStore(InputStream source, String password) throws RuntimeException {

		// Get the keystore instance:
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance(KEYSTORE_TYPE, SecurityProvider.getProviderName());
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error creating new key store.", e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Unable to locate provider. Are the BouncyCastle libraries installed?", e);
		}

		// Load the store using the given parameters:
		try {
			keyStore.load(source, password.toCharArray());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to initialise keystore - no such algorithm.", e);
		} catch (CertificateException e) {
			throw new RuntimeException("Unable to initialise keystore - certificate error.", e);
		} catch (IOException e) {
			throw new RuntimeException("Unable to initialise keystore - IO exception.", e);
		}

		return keyStore;
	}

	/**
	 * Retrieves a secret/symmetric key from the given keystore, as per
	 * {@link KeyStore#getEntry(String, java.security.KeyStore.ProtectionParameter)} .
	 * 
	 * @param keyStore
	 *            The {@link KeyStore} from which the key should be retrieved.
	 * @param alias
	 *            The name of the key.
	 * @return The specified key.
	 * @throws RuntimeException
	 *             If an error occurs in retrieving the key, of if key does not exist or is of the
	 *             wrong type.
	 */
	public SecretKey getSecretKey(KeyStore keyStore, String alias) throws RuntimeException {

		try {

			// Check the alias is valid:
			checkAlias(keyStore, alias, KeyStore.SecretKeyEntry.class);

			// Retrieve the key:
			KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);
			return entry.getSecretKey();

		} catch (KeyStoreException e) {
			throw new RuntimeException("Error accessing secret key for " + alias, e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to retrieve key - no such algorithm.", e);
		} catch (UnrecoverableEntryException e) {
			throw new RuntimeException("Unable to retrieve key - the key cannot be recovered.", e);
		}
	}

	/**
	 * Retrieves a private asymmetric key from the given keystore, as per
	 * {@link KeyStore#getEntry(String, java.security.KeyStore.ProtectionParameter)} .
	 * 
	 * @param keyStore
	 *            The {@link KeyStore} from which the key should be retrieved.
	 * @param alias
	 *            The name of the key.
	 * @return The specified key.
	 * @throws RuntimeException
	 *             If an error occurs in retrieving the key, of if key does not exist or is of the
	 *             wrong type.
	 */
	public PrivateKey getPrivateKey(KeyStore keyStore, String alias) throws RuntimeException {

		try {

			// Check the alias is valid:
			checkAlias(keyStore, alias, KeyStore.PrivateKeyEntry.class);

			// Retrieve the key:
			KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
			return entry.getPrivateKey();

		} catch (KeyStoreException e) {
			throw new RuntimeException("Error accessing secret key for " + alias, e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to retrieve key - no such algorithm.", e);
		} catch (UnrecoverableEntryException e) {
			throw new RuntimeException("Unable to retrieve key - the key cannot be recovered.", e);
		}
	}

	/**
	 * This method checks that an entry with the given alias exists in the given {@link KeyStore}
	 * and that it is of the specified type.
	 * 
	 * @param keyStore
	 *            The {@link KeyStore} to be checked.
	 * @param alias
	 *            The alias to be checked.
	 * @param type
	 *            The expected type of the key.
	 * @throws RuntimeException
	 *             If an error occurs in accessing the {@link KeyStore}.
	 */
	void checkAlias(KeyStore keyStore, String alias, Class<? extends KeyStore.Entry> type) throws RuntimeException {

		try {
			// Check the alias is valid:
			if (!keyStore.containsAlias(alias)) {
				throw new IllegalArgumentException("The key alias " + alias + " is not present in this keystore.");
			}
			if (!keyStore.entryInstanceOf(alias, type)) {
				throw new IllegalArgumentException("The key alias " + alias
						+ " is present in this keystore, but is not a " + KeyStore.SecretKeyEntry.class.getSimpleName()
						+ " entry.");
			}

		} catch (KeyStoreException e) {
			throw new RuntimeException("Error accessing secret key for " + alias, e);
		}
	}

	/**
	 * Places a secret key into the given keystore, as per
	 * {@link KeyStore#setEntry(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)}
	 * .
	 * 
	 * @param keyStore
	 *            The {@link KeyStore} into which the key should be placed.
	 * @param alias
	 *            The name to give this key.
	 * @param secretKey
	 *            The key to be placed in the keystore.
	 * @throws RuntimeException
	 *             If an error occurs in setting the entry.
	 */
	public void setSecretKey(KeyStore keyStore, String alias, SecretKey secretKey) throws RuntimeException {
		try {
			keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(secretKey), null);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error storing secret key for " + alias, e);
		}
	}

	/**
	 * Places the given asymmetric private key into the given keystore, as per
	 * {@link KeyStore#setEntry(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)}
	 * .
	 * 
	 * @param keyStore
	 *            The {@link KeyStore} into which the key should be placed.
	 * @param alias
	 *            The name to give this key.
	 * @param pair
	 *            The key pair whose private key will be placed in the keystore.
	 * @throws RuntimeException
	 *             If an error occurs in setting the entry.
	 */
	public void setPrivateKey(KeyStore keyStore, String alias, KeyPair pair) throws RuntimeException {
		try {
			keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(pair.getPrivate(),
					new Certificate[] {generateRootCert(pair)}), null);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Error storing secret key for " + alias, e);
		} catch (Exception e) {
			throw new RuntimeException("Error generating certificate for key " + alias, e);
		}
	}

	/**
	 * TODO: This method is taken from the Beginning Cryptography With Java examples. We should find
	 * a more correct way of handling this.
	 * <p>
	 * Generate a sample V1 certificate to use as a CA root certificate
	 * 
	 * @param pair
	 *            The user's public-private key pair.
	 * @return An {@link X509Certificate}, suitable for adding keys to a key-store.
	 * @throws Exception
	 *             This is a broad throws clause in order to catch multiple exceptions thrown when
	 *             generating a certificate.
	 */
	public static X509Certificate generateRootCert(KeyPair pair) throws Exception {
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(1));
		certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
		certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

		return certGen.generate(pair.getPrivate(), "BC");
	}

}
