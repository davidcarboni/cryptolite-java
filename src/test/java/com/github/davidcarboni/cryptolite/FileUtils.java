package com.github.davidcarboni.cryptolite;

import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Utility class to generate and compares random files to support the tests.
 *
 * @author David Carboni
 */
class FileUtils {

    /**
     * Generates a new file, containing random content. The file is a temp file, which will be
     * deleted on exit. Content is written using
     * {@link org.apache.commons.io.FileUtils#writeByteArrayToFile(File, byte[])}, handling any
     * {@link IOException} thrown.
     *
     * @return The created file.
     * @see org.apache.commons.io.FileUtils#writeByteArrayToFile(File, byte[])
     */
    public static Path newFile() throws IOException {

        final int filesize = 256;

        // Create a temp file:
        Path file = Files.createTempFile(FileUtils.class.getSimpleName(), "testFile");

        try (InputStream input = inputStream(filesize); OutputStream output = Files.newOutputStream(file)) {
            IOUtils.copy(input, output);
        }

        // Return the file:
        return file;
    }

    /**
     * Convenience method to instantiate an {@link InputStream} of random data of the specified
     * length.
     *
     * @param length The length of the stream.
     * @return An {@link InputStream} which will provide the specified number of random bytes.
     */
    public static InputStream inputStream(final long length) {
        return new InputStream() {
            int count;

            @Override
            public int read() throws IOException {
                if (count++ < length) {
                    return ((int) Generate.byteArray(1)[0]) & 0xff;
                    // For Java 8: return Byte.toUnsignedInt(bytes(1)[0]);
                } else {
                    return -1;
                }
            }
        };
    }

    /**
     * Compares two files using {@link org.apache.commons.io.FileUtils#contentEquals(File, File)},
     * handling any {@link IOException} thrown.
     *
     * @param f1 The first file.
     * @param f2 The second file.
     * @return If the content of the two files is equal, true.
     * @see org.apache.commons.io.FileUtils#contentEquals(File, File)
     */
    public static boolean sameFile(File f1, File f2) throws IOException {

        return org.apache.commons.io.FileUtils.contentEquals(f1, f2);
    }
}
