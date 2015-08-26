package com.github.davidcarboni.cryptolite;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.security.Provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

/**
 * Test for {@link SecurityProvider}.
 *
 * @author David Carboni
 */
public class SecurityProviderTest {
    /**
     * Clears the cached instance.
     *
     * @throws NoSuchFieldException   {@link NoSuchFieldException}
     * @throws IllegalAccessException {@link IllegalAccessException}
     */
    @Before
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        Field field = SecurityProvider.class.getDeclaredField("provider");
        field.setAccessible(true);
        field.set(SecurityProvider.class, null);
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.SecurityProvider#getProvider()}
     * . Checks that the provider instance is cached after the first call.
     */
    @Test
    public void testGetProvider() {

        // Given
        Provider firstCall;
        Provider secondCall;

        // When
        firstCall = SecurityProvider.getProvider();
        secondCall = SecurityProvider.getProvider();

        // Then
        assertSame(firstCall, secondCall);
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, firstCall.getName());
    }

    /**
     * Test method for
     * {@link com.github.davidcarboni.cryptolite.SecurityProvider#getProviderName()}
     * .
     */
    @Test
    public void testGetProviderName() {

        // Given
        String expectedName = BouncyCastleProvider.PROVIDER_NAME;

        // When
        String providerName = SecurityProvider.getProviderName();

        // Then
        Assert.assertEquals(expectedName, providerName);
    }

}
