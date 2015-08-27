package com.github.davidcarboni.cryptolite;

import java.security.Provider;
import java.security.Security;

/**
 * @author David Carboni
 */
public class SecurityProvider {

    /**
     * The name of an additional security provider. Default is Bouncycastle.
     */
    public static String providerName = "bc";

    /**
     * The name of an additional security provider class. Default is Bouncycastle.
     */
    public static String providerClassName = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private static Provider provider;

    /**
     * Attempts to add the provider specified by {@link #providerClassName}.
     *
     * @return If the provider is not already installed and is successfully added, true.
     * This enables methods to determine whether they should retry a failed operation if a new provider was successfully added.
     */
    public static boolean addProvider() {
        boolean result = false;

        if (provider == null) {

            // Check whether the provider has already been installed:
            Provider provider = Security.getProvider(providerName);

            // If not, attempt to install it:
            if (provider == null) {
                if ((provider = instantiate()) != null) {
                    Security.addProvider(provider);
                }
            }

            // Now cache the provider:
            SecurityProvider.provider = provider;

            result = provider != null;
        }

        return result;
    }

    /**
     * @return A new instance of {@link #providerClassName} if the class can be found, instantiated and is an instance of {@link Provider}.
     */
    private static Provider instantiate() {
        Provider result;
        try {
            Class<?> providerClass = Class.forName(providerClassName);
            result = (Provider) providerClass.newInstance();
        } catch (ClassNotFoundException e) {
            System.out.println("Unable to locate class " + providerClassName);
            result = null;
        } catch (InstantiationException e) {
            System.out.println("Unable to instantiate class " + providerClassName);
            result = null;
        } catch (IllegalAccessException e) {
            System.out.println("Unable to access class " + providerClassName);
            result = null;
        } catch (ClassCastException e) {
            System.out.println("Unable to cast class " + providerClassName + " to " + Provider.class.getName());
            result = null;
        }
        return result;
    }
}
