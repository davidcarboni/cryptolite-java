package com.github.davidcarboni;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

import java.lang.reflect.Field;
import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;

/**
 * 
 * Test for {@link Random}.
 * 
 * @author David Carboni
 * 
 */
public class RandomTest {

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
		Field field = Random.class.getDeclaredField("secureRandom");
		field.setAccessible(true);
		field.set(Random.class, null);
	}

	/**
	 * Test method for {@link com.github.davidcarboni.Random#getInstance()}. Checks that
	 * {@link Random#getInstance()} returns the same instance on every call, avoiding initialising a
	 * new instance every time.
	 */
	@Test
	public void testGetInstance() {

		// Given
		SecureRandom firstCall;
		SecureRandom secondCall;

		// When
		firstCall = Random.getInstance();
		secondCall = Random.getInstance();

		// Then
		assertSame(firstCall, secondCall);
	}

	/**
	 * Test method for {@link com.github.davidcarboni.Random#generateId()}. This checks that the
	 * number of bits in the returned ID is the same as specified by {@link Random#ID_BITS}.
	 */
	@Test
	public void shouldGenerateIdOfExpectedLength() {

		// Given
		String id;
		// The number of bits expected in the random ID:
		final int bits = Random.ID_BITS;
		// The number of bits in a byte:
		final int byteSize = 8;
		// The number of characters needed in a hex string to represent a byte:
		final int hexSize = 2;
		final int stringLength = (bits / byteSize) * hexSize;

		// When
		id = Random.generateId();

		// Then
		assertEquals(stringLength, id.length());
	}

	/**
	 * Test method for {@link com.github.davidcarboni.Random#generateSalt()}. This checks that the
	 * number of bytes in the returned salt value matches the length specified in
	 * {@link Random#SALT_BYTES}.
	 */
	@Test
	public void shouldGenerateSaltOfExpectedLength() {

		// Given
		String salt;

		// When
		salt = Random.generateSalt();

		// Then
		assertEquals(Random.SALT_BYTES, Codec.fromBase64String(salt).length);
	}

	/**
	 * Test method for {@link com.github.davidcarboni.Random#generatePassword(int)}. This checks
	 * that the number of characters in the returned password matches the specified length of the
	 * password.
	 */
	@Test
	public void shouldGeneratePasswordOfSpecifiedLength() {

		// Given
		String password;
		final int maxSize = 100;

		for (int i = 1; i < maxSize; i++) {
			// When
			password = Random.generatePassword(i);

			// Then
			assertEquals(i, password.length());
		}
	}

	/**
	 * Test the general randomness of ID generation. If this test fails, consider yourself
	 * astoundingly lucky.. or check the code is really producing random numbers.
	 */
	@Test
	public void testRandomnessId() {

		final int iterations = 1000;
		for (int i = 0; i < iterations; i++) {

			// Given
			String id1;
			String id2;

			// When
			id1 = Random.generateId();
			id2 = Random.generateId();

			// Then
			assertFalse(id1.equals(id2));
		}
	}

	/**
	 * Test the general randomness of salt generation. If this test fails, consider yourself
	 * astoundingly lucky.. or check the code is really producing random numbers.
	 */
	@Test
	public void testRandomnessSalt() {

		final int iterations = 1000;
		for (int i = 0; i < iterations; i++) {

			// Given
			String salt1;
			String salt2;

			// When
			salt1 = Random.generateSalt();
			salt2 = Random.generateSalt();

			// Then
			assertFalse(salt1.equals(salt2));
		}
	}

	/**
	 * Test the general randomness of password generation. If this test fails, consider yourself
	 * astoundingly lucky.. or check the code is really producing random numbers.
	 */
	@Test
	public void shouldProduceRandomPasswords() {

		final int iterations = 1000;
		final int passwordSize = 8;
		for (int i = 0; i < iterations; i++) {

			// Given
			String password1;
			String password2;

			// When
			password1 = Random.generatePassword(passwordSize);
			password2 = Random.generatePassword(passwordSize);

			// Then
			assertFalse(password1.equals(password2));
		}
	}

}
