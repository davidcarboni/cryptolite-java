package org.workdocx.cryptolite;

import java.io.File;
import java.io.IOException;

/**
 * 
 * Utility class to generate and compares random files to support the tests.
 * 
 * @author David Carboni
 * 
 */
class FileUtils {

	/**
	 * Generates a new file, containing random content. The file is a temp file, which will be
	 * deleted on exit. Content is written using
	 * {@link org.apache.commons.io.FileUtils#writeByteArrayToFile(File, byte[])}, handling any
	 * {@link IOException} thrown.
	 * 
	 * @return The created file.
	 * 
	 * @see org.apache.commons.io.FileUtils#writeByteArrayToFile(File, byte[])
	 */
	public static File newFile() {

		final int filesize = 256;

		// Create a temp file:
		File file;
		try {
			file = File.createTempFile(FileUtils.class.getSimpleName(), "testFile");
		} catch (IOException e) {
			throw new RuntimeException("Error creating temp file.", e);
		}
		file.deleteOnExit();

		// Generate some content:
		byte[] data = new byte[filesize];
		Random.getInstance().nextBytes(data);

		try {
			org.apache.commons.io.FileUtils.writeByteArrayToFile(file, data);
		} catch (IOException e) {
			throw new RuntimeException("Unable to create a temporary file: " + file.getPath(), e);
		}

		// Return the file:
		return file;
	}

	/**
	 * Compares two files using {@link org.apache.commons.io.FileUtils#contentEquals(File, File)},
	 * handling any {@link IOException} thrown.
	 * 
	 * @param f1
	 *            The first file.
	 * @param f2
	 *            The second file.
	 * @return If the content of the two files is equal, true.
	 * 
	 * @see org.apache.commons.io.FileUtils#contentEquals(File, File)
	 */
	public static boolean sameFile(File f1, File f2) {

		try {
			return org.apache.commons.io.FileUtils.contentEquals(f1, f2);
		} catch (IOException e) {
			throw new RuntimeException("Unable to compare files " + f1.getPath() + " and " + f2.getPath(), e);
		}
	}
}
