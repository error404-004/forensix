package com.forensix.util;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Validates and sanitizes filesystem paths to prevent path traversal and arbitrary system file access.
 */
public final class PathValidator {

    private PathValidator() {}

    /**
     * Validates that the provided path string is non-empty, does not attempt directory traversal (..),
     * and points to an existing readable directory.
     *
     * @param pathString directory path to validate
     * @return normalized real Path
     * @throws IllegalArgumentException if path is invalid or attempts directory traversal
     */
    public static Path validateDirectory(String pathString) {
        if (pathString == null || pathString.trim().isEmpty()) {
            throw new IllegalArgumentException("Directory path cannot be empty");
        }

        // Strict security: Check for path traversal sequence before any path normalization
        if (pathString.contains("..")) {
            throw new IllegalArgumentException("Path traversal sequence '..' is not allowed: " + pathString);
        }

        Path path = Paths.get(pathString.trim()).normalize();

        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Directory does not exist: " + pathString);
        }

        if (!Files.isDirectory(path)) {
            throw new IllegalArgumentException("Path is not a directory: " + pathString);
        }

        if (!Files.isReadable(path)) {
            throw new IllegalArgumentException("Directory is not readable (permission denied): " + pathString);
        }

        return path.toAbsolutePath().normalize();
    }

    /**
     * Validates a log file path exists and is a readable regular file.
     */
    public static Path validateLogFile(String pathString) {
        if (pathString == null || pathString.trim().isEmpty()) {
            throw new IllegalArgumentException("Log file path cannot be empty");
        }

        // Strict security: Check for path traversal sequence before any path normalization
        if (pathString.contains("..")) {
            throw new IllegalArgumentException("Path traversal sequence '..' is not allowed in log file path: " + pathString);
        }

        Path path = Paths.get(pathString.trim()).normalize();

        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Log file does not exist: " + pathString);
        }

        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Log path is not a regular file: " + pathString);
        }

        if (!Files.isReadable(path)) {
            throw new IllegalArgumentException("Log file is not readable: " + pathString);
        }

        return path.toAbsolutePath().normalize();
    }

    /**
     * Normalizes a relative path string using forward slashes for deterministic cross-platform comparison.
     */
    public static String toStandardRelativePath(Path root, Path file) {
        Path rel = root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize());
        return rel.toString().replace(File.separatorChar, '/');
    }
}
