package com.github.davidcarboni.cryptolite;

import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
     * {@link com.github.davidcarboni.cryptolite.SecurityProvider#addProvider()}
     * . Checks that the provider instance is cached after the first call.
     */
    @Test
    public void shouldAddProvider() {

        // Given
        boolean firstCall;
        boolean secondCall;

        // When
        firstCall = SecurityProvider.addProvider();
        secondCall = SecurityProvider.addProvider();

        // Then
        assertTrue(firstCall);
        assertFalse(secondCall);
    }

}
