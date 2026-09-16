package com.forensix.service;

import com.forensix.model.FileEvent;
import com.forensix.model.FileRecord;

import java.nio.file.Path;
import java.util.List;

/**
 * Service contract for File Integrity Monitoring (FIM).
 * Computes baseline hashes and performs cryptographic diffing on scans.
 */
public interface IntegrityScanner {

    /**
     * Walks the target directory, computes streaming SHA-256 hashes for all files,
     * and persists the baseline state to the database.
     *
     * @param rootPath target directory to baseline
     * @return list of newly created FileRecords
     */
    List<FileRecord> createBaseline(Path rootPath);

    /**
     * Re-scans the target directory, calculates current cryptographic hashes,
     * compares against the existing baseline in the database, and records detected changes.
     *
     * @param rootPath target directory to scan
     * @param scanId associated scan session ID
     * @return list of FileEvents (ADDED, MODIFIED, DELETED, UNCHANGED, SCAN_ERROR)
     */
    List<FileEvent> scan(Path rootPath, long scanId);
}
