package com.forensix;

import com.forensix.dao.AuditLogDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.model.AuditRecord;
import com.forensix.model.LogEntry;
import com.forensix.service.AuditService;
import com.forensix.service.AuditServiceImpl;
import com.forensix.service.LogAnalyzerImpl;
import com.forensix.service.VerificationResult;
import com.forensix.util.PathValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityAndEdgeCaseTest {

    @TempDir
    Path tempDir;

    private DatabaseManager dbManager;
    private AuditLogDAO auditLogDAO;
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        Path dbPath = tempDir.resolve("sec_test.db");
        dbManager = new DatabaseManager(dbPath.toString());
        dbManager.initSchema();
        auditLogDAO = new AuditLogDAO(dbManager);
        auditService = new AuditServiceImpl(auditLogDAO);
    }

    @Test
    @DisplayName("Verify path traversal injection rejection")
    void testPathTraversalRejection() {
        assertThrows(IllegalArgumentException.class, () -> PathValidator.validateDirectory("../some/traversal"));
        assertThrows(IllegalArgumentException.class, () -> PathValidator.validateDirectory("C:/folder/../../windows"));
        assertThrows(IllegalArgumentException.class, () -> PathValidator.validateLogFile("../../etc/passwd"));
        assertThrows(IllegalArgumentException.class, () -> PathValidator.validateDirectory(""));
        assertThrows(IllegalArgumentException.class, () -> PathValidator.validateDirectory(null));
    }

    @Test
    @DisplayName("Verify thread safety of sequential hash chain under concurrent load")
    void testConcurrentAuditLoggingIntegrity() throws InterruptedException {
        int threads = 8;
        int recordsPerThread = 25;
        int totalExpected = threads * recordsPerThread;

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(threads);

        for (int t = 0; t < threads; t++) {
            final int threadId = t;
            pool.submit(() -> {
                try {
                    for (int i = 0; i < recordsPerThread; i++) {
                        auditService.record(
                                AuditRecord.RecordType.SYSTEM,
                                threadId * 1000 + i,
                                "CONCURRENT_EVENT_T" + threadId + "_N" + i
                        );
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(totalExpected, auditService.getRecordCount());

        // Crucial: Despite concurrent writes, every single link must be strictly sequential and valid!
        VerificationResult result = auditService.verifyChain();
        assertTrue(result.isValid(), "Audit chain MUST remain 100% valid under concurrent writes: " + result.getMessage());
        assertEquals(totalExpected, result.getTotalRecordsVerified());
    }

    @Test
    @DisplayName("Verify log analyzer resilience against ReDoS and extreme line lengths")
    void testLogAnalyzerReDoSResilience() throws IOException {
        Path stressLog = tempDir.resolve("stress.log");
        List<String> lines = new ArrayList<>();

        // 1000 noisy malformed lines
        for (int i = 0; i < 1000; i++) {
            lines.add("||||||||||||||||||||||||||||||||||||||||||||");
            lines.add("A".repeat(5000)); // Large single token
            lines.add("2026-09-16 12:00:00 | <script>alert(1)</script> | INJECTION | 127.0.0.1");
        }
        Files.write(stressLog, lines);

        LogAnalyzerImpl analyzer = new LogAnalyzerImpl(null);
        List<LogEntry> parsed = analyzer.parse(stressLog);

        // Valid formatted line with script injection should be parsed safely as data without execution
        assertEquals(1000, parsed.size());
        assertEquals(2000, analyzer.getParseErrorsCount());
        assertEquals("<script>alert(1)</script>", parsed.get(0).getUser());
    }
}
