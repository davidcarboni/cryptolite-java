/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author David Carboni
 * 
 */
public class SecurityProvider {

	private static Provider provider;

	/**
	 * 
	 * @return A {@link BouncyCastleProvider} instance. If there is already a Bouncy Castle provider
	 *         installed, that instance will be returned, otherwise a new instance is created and
	 *         returned. The returned instance is cached for future calls.
	 */
	public static Provider getProvider() {

		if (SecurityProvider.provider == null) {

			// Check whether BouncyCastle has already been installed:
			Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

			// If not, install it:
			if (provider == null) {
				provider = new BouncyCastleProvider();
				Security.addProvider(provider);
			}

			// Now cache the provider:
			SecurityProvider.provider = provider;
		}

		return provider;
	}

	/**
	 * 
	 * @return The name of the cached provider, by calling {@link Provider#getName()} on the result
	 *         of {@link #getProvider()}.
	 */
	public static String getProviderName() {
		return getProvider().getName();
	}
}
