package com.forensix;

import com.forensix.util.HashUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HashUtilTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Verify known SHA-256 standard test vectors")
    void testKnownVectors() {
        // Standard SHA-256 of empty string
        String emptyHash = HashUtil.sha256("");
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash);

        // Standard SHA-256 of "hello world"
        String helloHash = HashUtil.sha256("hello world");
        assertEquals("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", helloHash);
    }

    @Test
    @DisplayName("Verify file hashing on empty file")
    void testEmptyFileHash() throws IOException {
        Path emptyFile = tempDir.resolve("empty.txt");
        Files.createFile(emptyFile);

        String hash = HashUtil.sha256(emptyFile);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    @Test
    @DisplayName("Verify streaming hashing on large 5MB file without memory overflow")
    void testLargeFileStreaming() throws IOException {
        Path largeFile = tempDir.resolve("large_file.dat");
        byte[] chunk = new byte[65536]; // 64 KB chunk
        Arrays.fill(chunk, (byte) 0x41); // filled with 'A'

        try (var os = Files.newOutputStream(largeFile)) {
            for (int i = 0; i < 80; i++) { // ~5.24 MB
                os.write(chunk);
            }
        }

        String hash = HashUtil.sha256(largeFile);
        assertNotNull(hash);
        assertEquals(64, hash.length());
    }

    @Test
    @DisplayName("Verify exception on non-existent file")
    void testNonExistentFile() {
        Path nonExistent = tempDir.resolve("does_not_exist.txt");
        assertThrows(IOException.class, () -> HashUtil.sha256(nonExistent));
    }
}
