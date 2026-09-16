package com.forensix;

import com.forensix.dao.AnomalyDAO;
import com.forensix.dao.AuditLogDAO;
import com.forensix.dao.BaselineDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.dao.EventDAO;
import com.forensix.dao.ScanDAO;
import com.forensix.model.Anomaly;
import com.forensix.model.AuditRecord;
import com.forensix.model.FileEvent;
import com.forensix.model.FileRecord;
import com.forensix.model.Scan;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseAndDAOTest {

    @TempDir
    Path tempDir;

    private DatabaseManager dbManager;
    private BaselineDAO baselineDAO;
    private ScanDAO scanDAO;
    private EventDAO eventDAO;
    private AnomalyDAO anomalyDAO;
    private AuditLogDAO auditLogDAO;

    @BeforeEach
    void setUp() {
        Path dbPath = tempDir.resolve("test_forensix.db");
        dbManager = new DatabaseManager(dbPath.toString());
        dbManager.initSchema();

        baselineDAO = new BaselineDAO(dbManager);
        scanDAO = new ScanDAO(dbManager);
        eventDAO = new EventDAO(dbManager);
        anomalyDAO = new AnomalyDAO(dbManager);
        auditLogDAO = new AuditLogDAO(dbManager);
    }

    @Test
    @DisplayName("Verify BaselineDAO insert, query, count, and clear")
    void testBaselineDAO() {
        assertEquals(0, baselineDAO.count());

        FileRecord r1 = new FileRecord("test/a.txt", "hash_a", 100, "2026-09-16T10:00:00Z");
        FileRecord r2 = new FileRecord("test/b.txt", "hash_b", 200, "2026-09-16T10:05:00Z");

        baselineDAO.insert(r1);
        baselineDAO.insert(r2);

        assertEquals(2, baselineDAO.count());
        List<FileRecord> all = baselineDAO.findAll();
        assertEquals(2, all.size());

        FileRecord fetched = baselineDAO.findByPath("test/a.txt");
        assertNotNull(fetched);
        assertEquals("hash_a", fetched.getHash());
        assertEquals(100, fetched.getSizeBytes());

        baselineDAO.clear();
        assertEquals(0, baselineDAO.count());
    }

    @Test
    @DisplayName("Verify ScanDAO, EventDAO, and AnomalyDAO operations")
    void testScanEventAnomalyDAOs() {
        long scanId = scanDAO.createScan("test/monitored");
        assertTrue(scanId > 0);

        Scan scan = scanDAO.findById(scanId);
        assertNotNull(scan);
        assertEquals("IN_PROGRESS", scan.getStatus());
        assertEquals("test/monitored", scan.getScannedDirectory());

        FileEvent event = new FileEvent(scanId, "test/file.txt", FileEvent.EventType.MODIFIED, "old_h", "new_h");
        long eventId = eventDAO.insert(event);
        assertTrue(eventId > 0);

        List<FileEvent> events = eventDAO.findByScanId(scanId);
        assertEquals(1, events.size());
        assertEquals(FileEvent.EventType.MODIFIED, events.get(0).getEventType());

        Anomaly anomaly = new Anomaly(scanId, "bad log line", "Brute Force", Anomaly.Severity.HIGH);
        long anomalyId = anomalyDAO.insert(anomaly);
        assertTrue(anomalyId > 0);

        List<Anomaly> anomalies = anomalyDAO.findByScanId(scanId);
        assertEquals(1, anomalies.size());
        assertEquals(Anomaly.Severity.HIGH, anomalies.get(0).getSeverity());

        scanDAO.updateScanStatus(scanId, "COMPLETED", "2026-09-16T10:30:00Z");
        Scan updated = scanDAO.findById(scanId);
        assertEquals("COMPLETED", updated.getStatus());
        assertEquals("2026-09-16T10:30:00Z", updated.getFinishedAt());
    }

    @Test
    @DisplayName("Verify AuditLogDAO append-only insert and ordered query")
    void testAuditLogDAO() {
        assertNull(auditLogDAO.getLastRecord());
        assertEquals(0, auditLogDAO.count());

        AuditRecord r1 = new AuditRecord(AuditRecord.RecordType.SYSTEM, 0, "INIT", AuditRecord.GENESIS_PREV_HASH, "hash1");
        long id1 = auditLogDAO.insert(r1);
        assertEquals(1, id1);

        AuditRecord r2 = new AuditRecord(AuditRecord.RecordType.FILE_EVENT, 10, "MODIFIED a.txt", "hash1", "hash2");
        long id2 = auditLogDAO.insert(r2);
        assertEquals(2, id2);

        assertEquals(2, auditLogDAO.count());
        AuditRecord last = auditLogDAO.getLastRecord();
        assertNotNull(last);
        assertEquals(id2, last.getId());
        assertEquals("hash2", last.getRecordHash());

        List<AuditRecord> ordered = auditLogDAO.findAllOrderedById();
        assertEquals(2, ordered.size());
        assertEquals(id1, ordered.get(0).getId());
        assertEquals(id2, ordered.get(1).getId());
    }
}
