package com.forensix.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility for streaming cryptographic hashing (SHA-256).
 * Ensures memory-efficient chunked hashing without loading entire files into heap.
 */
public final class HashUtil {

    private static final int BUFFER_SIZE = 8192; // 8 KB chunks
    public static final String SHA_256 = "SHA-256";

    private HashUtil() {}

    /**
     * Obtains a new MessageDigest instance for SHA-256.
     */
    public static MessageDigest getSha256Digest() {
        try {
            return MessageDigest.getInstance(SHA_256);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM missing SHA-256 algorithm support", e);
        }
    }

    /**
     * Calculates SHA-256 hash of a file using an 8KB streaming buffer.
     *
     * @param path target file path
     * @return 64-character lowercase hexadecimal hash string
     * @throws IOException if the file cannot be read
     */
    public static String sha256(Path path) throws IOException {
        if (!Files.exists(path)) {
            throw new IOException("File does not exist: " + path);
        }
        if (!Files.isRegularFile(path)) {
            throw new IOException("Path is not a regular file: " + path);
        }

        MessageDigest digest = getSha256Digest();
        try (InputStream is = new BufferedInputStream(Files.newInputStream(path), BUFFER_SIZE)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return bytesToHex(digest.digest());
    }

    /**
     * Calculates SHA-256 hash of a UTF-8 string.
     */
    public static String sha256(String text) {
        if (text == null) text = "";
        return sha256(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Calculates SHA-256 hash of a byte array.
     */
    public static String sha256(byte[] data) {
        MessageDigest digest = getSha256Digest();
        if (data != null && data.length > 0) {
            digest.update(data);
        }
        return bytesToHex(digest.digest());
    }

    /**
     * Converts raw bytes to a 64-character lowercase hexadecimal string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
