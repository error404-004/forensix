package com.forensix;

import com.forensix.dao.BaselineDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.dao.EventDAO;
import com.forensix.dao.ScanDAO;
import com.forensix.model.FileEvent;
import com.forensix.model.FileRecord;
import com.forensix.service.IntegrityScanner;
import com.forensix.service.IntegrityScannerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntegrityScannerImplTest {

    @TempDir
    Path tempDir;

    private DatabaseManager dbManager;
    private BaselineDAO baselineDAO;
    private EventDAO eventDAO;
    private ScanDAO scanDAO;
    private IntegrityScanner scanner;

    private Path monitoredDir;

    @BeforeEach
    void setUp() throws IOException {
        Path dbPath = tempDir.resolve("fim_test.db");
        dbManager = new DatabaseManager(dbPath.toString());
        dbManager.initSchema();

        baselineDAO = new BaselineDAO(dbManager);
        eventDAO = new EventDAO(dbManager);
        scanDAO = new ScanDAO(dbManager);
        scanner = new IntegrityScannerImpl(baselineDAO, eventDAO);

        monitoredDir = tempDir.resolve("monitored");
        Files.createDirectories(monitoredDir);
    }

    @Test
    @DisplayName("Verify baseline creation on sample files")
    void testCreateBaseline() throws IOException {
        Files.writeString(monitoredDir.resolve("file1.txt"), "Initial content 1");
        Files.writeString(monitoredDir.resolve("file2.txt"), "Initial content 2");
        Path subDir = monitoredDir.resolve("sub");
        Files.createDirectories(subDir);
        Files.writeString(subDir.resolve("file3.txt"), "Sub content 3");

        List<FileRecord> records = scanner.createBaseline(monitoredDir);
        assertEquals(3, records.size());
        assertEquals(3, baselineDAO.count());

        FileRecord r1 = baselineDAO.findByPath("file1.txt");
        assertNotNull(r1);
        assertNotNull(r1.getHash());
    }

    @Test
    @DisplayName("Verify scan detection: UNCHANGED, MODIFIED, ADDED, DELETED")
    void testScanDiffDetection() throws IOException {
        // Step 1: Create initial files and baseline
        Path f1 = monitoredDir.resolve("file1.txt");
        Path f2 = monitoredDir.resolve("file2.txt");
        Path f3 = monitoredDir.resolve("file3.txt");

        Files.writeString(f1, "Alpha");
        Files.writeString(f2, "Beta");
        Files.writeString(f3, "Gamma");

        scanner.createBaseline(monitoredDir);
        assertEquals(3, baselineDAO.count());

        // Step 2: Unchanged scan
        long scan1 = scanDAO.createScan(monitoredDir.toString());
        List<FileEvent> events1 = scanner.scan(monitoredDir, scan1);
        assertEquals(3, events1.size());
        assertTrue(events1.stream().allMatch(e -> e.getEventType() == FileEvent.EventType.UNCHANGED));

        // Step 3: Perform modifications:
        // - f1 is UNCHANGED
        // - f2 is MODIFIED
        Files.writeString(f2, "Beta Modified Content!");
        // - f3 is DELETED
        Files.delete(f3);
        // - f4 is ADDED
        Path f4 = monitoredDir.resolve("file4.txt");
        Files.writeString(f4, "Delta Brand New File");

        long scan2 = scanDAO.createScan(monitoredDir.toString());
        List<FileEvent> events2 = scanner.scan(monitoredDir, scan2);
        assertEquals(4, events2.size());

        Map<String, FileEvent.EventType> eventMap = events2.stream()
                .collect(Collectors.toMap(FileEvent::getPath, FileEvent::getEventType));

        assertEquals(FileEvent.EventType.UNCHANGED, eventMap.get("file1.txt"));
        assertEquals(FileEvent.EventType.MODIFIED, eventMap.get("file2.txt"));
        assertEquals(FileEvent.EventType.DELETED, eventMap.get("file3.txt"));
        assertEquals(FileEvent.EventType.ADDED, eventMap.get("file4.txt"));

        // Verify stored in DB
        List<FileEvent> dbEvents = eventDAO.findByScanId(scan2);
        assertEquals(4, dbEvents.size());
    }

    @Test
    @DisplayName("Verify empty directory baseline")
    void testEmptyDirectory() {
        List<FileRecord> records = scanner.createBaseline(monitoredDir);
        assertEquals(0, records.size());
        assertEquals(0, baselineDAO.count());

        long scanId = scanDAO.createScan(monitoredDir.toString());
        List<FileEvent> events = scanner.scan(monitoredDir, scanId);
        assertEquals(0, events.size());
    }

    @Test
    @DisplayName("Verify invalid path validation rejection")
    void testInvalidDirectory() {
        Path invalid = tempDir.resolve("non_existent_folder");
        assertThrows(IllegalArgumentException.class, () -> scanner.createBaseline(invalid));
    }
}
