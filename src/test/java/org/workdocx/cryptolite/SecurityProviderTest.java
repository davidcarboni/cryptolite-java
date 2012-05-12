/**
 * Copyright (C) 2011 WorkDocx Ltd.
 */
package org.workdocx.cryptolite;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import java.lang.reflect.Field;
import java.security.Provider;

import junit.framework.Assert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * Test for {@link SecurityProvider}.
 * 
 * @author David Carboni
 * 
 */
public class SecurityProviderTest {
	/**
	 * Clears the cached instance.
	 * 
	 * @throws NoSuchFieldException
	 *             {@link NoSuchFieldException}
	 * @throws IllegalAccessException
	 *             {@link IllegalAccessException}
	 */
	@Before
	public void setUp() throws NoSuchFieldException, IllegalAccessException {
		Field field = SecurityProvider.class.getDeclaredField("provider");
		field.setAccessible(true);
		field.set(SecurityProvider.class, null);
	}

	/**
	 * Test method for {@link org.workdocx.cryptolite.SecurityProvider#getProvider()}. Checks that
	 * the provider instance is cached after the first call.
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
	 * Test method for {@link org.workdocx.cryptolite.SecurityProvider#getProviderName()}.
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
