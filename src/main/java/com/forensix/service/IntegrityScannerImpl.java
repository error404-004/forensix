package com.forensix.service;

import com.forensix.dao.BaselineDAO;
import com.forensix.dao.EventDAO;
import com.forensix.model.FileEvent;
import com.forensix.model.FileRecord;
import com.forensix.util.HashUtil;
import com.forensix.util.PathValidator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Implementation of IntegrityScanner.
 * Employs streaming SHA-256 hashing and differential state comparison.
 */
public class IntegrityScannerImpl implements IntegrityScanner {
    private static final Logger LOGGER = Logger.getLogger(IntegrityScannerImpl.class.getName());

    private final BaselineDAO baselineDAO;
    private final EventDAO eventDAO;

    public IntegrityScannerImpl(BaselineDAO baselineDAO, EventDAO eventDAO) {
        this.baselineDAO = baselineDAO;
        this.eventDAO = eventDAO;
    }

    @Override
    public List<FileRecord> createBaseline(Path rootPath) {
        Path validatedRoot = PathValidator.validateDirectory(rootPath.toString());
        LOGGER.info("Starting baseline creation for directory: " + validatedRoot);

        List<FileRecord> records = new ArrayList<>();

        try (Stream<Path> stream = Files.walk(validatedRoot)) {
            stream.filter(Files::isRegularFile)
                  // Security: avoid following symlinks pointing outside the monitored root
                  .filter(p -> p.toAbsolutePath().normalize().startsWith(validatedRoot))
                  .forEach(file -> {
                      String relPath = PathValidator.toStandardRelativePath(validatedRoot, file);
                      try {
                          String hash = HashUtil.sha256(file);
                          long size = Files.size(file);
                          FileTime mtime = Files.getLastModifiedTime(file);
                          FileRecord record = new FileRecord(relPath, hash, size, mtime.toInstant().toString());
                          records.add(record);
                      } catch (IOException e) {
                          LOGGER.log(Level.WARNING, "Failed to hash file during baseline: " + relPath, e);
                      }
                  });
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to walk directory during baseline: " + validatedRoot, e);
            throw new RuntimeException("Directory traversal failed", e);
        }

        // Replace previous baseline with freshly established baseline
        baselineDAO.clear();
        baselineDAO.insertBatch(records);
        LOGGER.info("Baseline creation complete. Recorded " + records.size() + " files.");
        return records;
    }

    @Override
    public List<FileEvent> scan(Path rootPath, long scanId) {
        Path validatedRoot = PathValidator.validateDirectory(rootPath.toString());
        LOGGER.info("Starting integrity scan #" + scanId + " on: " + validatedRoot);

        // Fetch stored baseline map: relativePath -> FileRecord
        List<FileRecord> baselineList = baselineDAO.findAll();
        Map<String, FileRecord> baselineMap = new HashMap<>();
        for (FileRecord r : baselineList) {
            baselineMap.put(r.getPath(), r);
        }

        List<FileEvent> events = new ArrayList<>();
        Set<String> scannedRelPaths = new HashSet<>();

        // Walk current filesystem state
        try (Stream<Path> stream = Files.walk(validatedRoot)) {
            stream.filter(Files::isRegularFile)
                  .filter(p -> p.toAbsolutePath().normalize().startsWith(validatedRoot))
                  .forEach(file -> {
                      String relPath = PathValidator.toStandardRelativePath(validatedRoot, file);
                      scannedRelPaths.add(relPath);

                      FileRecord baselineRecord = baselineMap.get(relPath);
                      String oldHash = baselineRecord != null ? baselineRecord.getHash() : null;

                      try {
                          String currentHash = HashUtil.sha256(file);

                          if (baselineRecord == null) {
                              // File exists on disk but was not in baseline -> ADDED
                              events.add(new FileEvent(scanId, relPath, FileEvent.EventType.ADDED, null, currentHash));
                          } else if (!currentHash.equalsIgnoreCase(oldHash)) {
                              // File exists in both but hash differs -> MODIFIED
                              events.add(new FileEvent(scanId, relPath, FileEvent.EventType.MODIFIED, oldHash, currentHash));
                          } else {
                              // Hash is identical -> UNCHANGED
                              events.add(new FileEvent(scanId, relPath, FileEvent.EventType.UNCHANGED, oldHash, currentHash));
                          }
                      } catch (IOException e) {
                          LOGGER.log(Level.WARNING, "Error hashing file during scan: " + relPath, e);
                          events.add(new FileEvent(scanId, relPath, FileEvent.EventType.SCAN_ERROR, oldHash, null, e.getMessage()));
                      }
                  });
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to traverse directory during scan: " + validatedRoot, e);
            throw new RuntimeException("Integrity scan filesystem traversal failed", e);
        }

        // Check for DELETED files: present in baseline but absent from disk
        for (Map.Entry<String, FileRecord> entry : baselineMap.entrySet()) {
            String relPath = entry.getKey();
            if (!scannedRelPaths.contains(relPath)) {
                events.add(new FileEvent(scanId, relPath, FileEvent.EventType.DELETED, entry.getValue().getHash(), null));
            }
        }

        // Persist events to database
        eventDAO.insertBatch(events);
        LOGGER.info("Integrity scan #" + scanId + " finished. Detected " + events.size() + " total events.");
        return events;
    }
}
