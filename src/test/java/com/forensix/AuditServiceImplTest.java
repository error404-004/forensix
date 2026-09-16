package com.forensix;

import com.forensix.dao.AuditLogDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.model.AuditRecord;
import com.forensix.service.AuditService;
import com.forensix.service.AuditServiceImpl;
import com.forensix.service.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditServiceImplTest {

    @TempDir
    Path tempDir;

    private DatabaseManager dbManager;
    private AuditLogDAO auditLogDAO;
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        Path dbPath = tempDir.resolve("disposable_audit_test.db");
        dbManager = new DatabaseManager(dbPath.toString());
        dbManager.initSchema();
        auditLogDAO = new AuditLogDAO(dbManager);
        auditService = new AuditServiceImpl(auditLogDAO);
    }

    @Test
    @DisplayName("Verify clean audit hash-chain creation and verification")
    void testCleanAuditChain() {
        // Initially empty
        VerificationResult emptyRes = auditService.verifyChain();
        assertTrue(emptyRes.isValid());
        assertEquals(0, emptyRes.getTotalRecordsVerified());

        // Append 5 records
        AuditRecord r1 = auditService.record(AuditRecord.RecordType.SYSTEM, 0, "SYSTEM_STARTUP");
        AuditRecord r2 = auditService.record(AuditRecord.RecordType.BASELINE, 1, "BASELINE_CREATED: 4 files");
        AuditRecord r3 = auditService.record(AuditRecord.RecordType.SCAN, 1, "SCAN_COMPLETED: 1 change");
        AuditRecord r4 = auditService.record(AuditRecord.RecordType.FILE_EVENT, 10, "MODIFIED: /etc/passwd");
        AuditRecord r5 = auditService.record(AuditRecord.RecordType.ANOMALY, 20, "BRUTE_FORCE: 192.168.1.100");

        assertEquals(5, auditService.getRecordCount());

        // Verify genesis link
        assertEquals(AuditRecord.GENESIS_PREV_HASH, r1.getPrevHash());
        // Verify chain linkage
        assertEquals(r1.getRecordHash(), r2.getPrevHash());
        assertEquals(r2.getRecordHash(), r3.getPrevHash());
        assertEquals(r3.getRecordHash(), r4.getPrevHash());
        assertEquals(r4.getRecordHash(), r5.getPrevHash());

        // Verify chain integrity
        VerificationResult result = auditService.verifyChain();
        assertTrue(result.isValid(), "Clean audit chain must verify successfully");
        assertEquals(5, result.getTotalRecordsVerified());
    }

    @Test
    @DisplayName("Verify detection of manually tampered payload in disposable database")
    void testTamperDetectionPayloadModification() throws Exception {
        // Create 4 valid records
        auditService.record(AuditRecord.RecordType.SYSTEM, 0, "INITIAL_RECORD");
        auditService.record(AuditRecord.RecordType.FILE_EVENT, 1, "ORIGINAL_FILE_A");
        auditService.record(AuditRecord.RecordType.FILE_EVENT, 2, "ORIGINAL_FILE_B (TARGET)");
        auditService.record(AuditRecord.RecordType.SCAN, 1, "FINAL_SCAN_SUMMARY");

        // Prior to tampering, chain is valid
        assertTrue(auditService.verifyChain().isValid());

        // Simulate external attacker tampering directly with SQLite file row 3
        try (Connection conn = dbManager.getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("UPDATE audit_log SET payload = 'TAMPERED_COVER_TRACKS' WHERE id = 3;");
        }

        // Run audit chain verification
        VerificationResult result = auditService.verifyChain();
        assertFalse(result.isValid(), "Tampered record must fail verification");
        assertEquals(3, result.getBrokenRecordId(), "Must pinpoint record #3 as the tampered record");
        assertEquals("RECORD_HASH_MISMATCH", result.getBrokenField());
        assertNotNull(result.getExpectedHash());
        assertNotNull(result.getActualHash());
    }

    @Test
    @DisplayName("Verify detection of broken previous hash linkage")
    void testTamperDetectionPrevHashLinkBreak() throws Exception {
        auditService.record(AuditRecord.RecordType.SYSTEM, 0, "REC_1");
        auditService.record(AuditRecord.RecordType.FILE_EVENT, 1, "REC_2");
        auditService.record(AuditRecord.RecordType.FILE_EVENT, 2, "REC_3");

        // Corrupt prev_hash of record 2
        try (Connection conn = dbManager.getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("UPDATE audit_log SET prev_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE id = 2;");
        }

        VerificationResult result = auditService.verifyChain();
        assertFalse(result.isValid());
        assertEquals(2, result.getBrokenRecordId());
        assertEquals("PREV_HASH_MISMATCH", result.getBrokenField());
    }
}
