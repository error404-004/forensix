package com.forensix;

import com.forensix.dao.AnomalyDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.dao.ScanDAO;
import com.forensix.model.Anomaly;
import com.forensix.model.LogEntry;
import com.forensix.service.LogAnalyzerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogAnalyzerImplTest {

    @TempDir
    Path tempDir;

    private DatabaseManager dbManager;
    private AnomalyDAO anomalyDAO;
    private ScanDAO scanDAO;
    private LogAnalyzerImpl analyzer;
    private long testScanId;

    @BeforeEach
    void setUp() {
        Path dbPath = tempDir.resolve("log_test.db");
        dbManager = new DatabaseManager(dbPath.toString());
        dbManager.initSchema();
        anomalyDAO = new AnomalyDAO(dbManager);
        scanDAO = new ScanDAO(dbManager);
        analyzer = new LogAnalyzerImpl(anomalyDAO);

        testScanId = scanDAO.createScan("logs");
    }

    @Test
    @DisplayName("Verify parsing normal and malformed log lines")
    void testParseLogFile() throws IOException {
        Path logFile = tempDir.resolve("auth.log");
        List<String> lines = List.of(
                "# Header comment",
                "2026-09-16 10:00:00 | alice | SUCCESS_LOGIN | 192.168.1.10",
                "MALFORMED_LINE_WITHOUT_PIPES",
                "2026-09-16 10:01:00 | bob | FAILED_LOGIN | 192.168.1.20",
                "",
                "2026-09-16 10:02:00 | missing_fields"
        );
        Files.write(logFile, lines);

        List<LogEntry> entries = analyzer.parse(logFile);
        assertEquals(2, entries.size());
        assertEquals(2, analyzer.getParseErrorsCount());

        LogEntry e1 = entries.get(0);
        assertEquals("alice", e1.getUser());
        assertEquals("SUCCESS_LOGIN", e1.getEvent());
        assertEquals("192.168.1.10", e1.getIp());
    }

    @Test
    @DisplayName("Verify boundary condition for failed login threshold (4 vs 5)")
    void testFailedLoginThresholdBoundary() {
        List<LogEntry> entries = new ArrayList<>();
        // 4 failed logins from 10.0.0.1
        for (int i = 0; i < 4; i++) {
            entries.add(new LogEntry(i + 1, "2026-09-16 10:0" + i + ":00", "user1", "FAILED_LOGIN", "10.0.0.1", "raw"));
        }

        List<Anomaly> anomalies4 = analyzer.evaluate(entries, testScanId);
        boolean hasBurst = anomalies4.stream().anyMatch(a -> a.getRuleTriggered().contains("Brute Force"));
        assertFalse(hasBurst, "4 failed attempts must NOT trigger brute force anomaly");

        // 5th failed login
        entries.add(new LogEntry(5, "2026-09-16 10:04:30", "user1", "FAILED_LOGIN", "10.0.0.1", "raw"));
        List<Anomaly> anomalies5 = analyzer.evaluate(entries, testScanId);
        boolean hasBurst5 = anomalies5.stream().anyMatch(a -> a.getRuleTriggered().contains("Brute Force"));
        assertTrue(hasBurst5, "5 failed attempts within 5 minutes MUST trigger brute force anomaly");
    }

    @Test
    @DisplayName("Verify threat intelligence blacklisted IP detection")
    void testBlacklistedIp() {
        analyzer.setBlacklistedIps(Set.of("198.51.100.99"));
        List<LogEntry> entries = List.of(
                new LogEntry(1, "2026-09-16 10:00:00", "attacker", "SUCCESS_LOGIN", "198.51.100.99", "raw")
        );

        List<Anomaly> anomalies = analyzer.evaluate(entries, testScanId);
        assertEquals(1, anomalies.size());
        assertEquals(Anomaly.Severity.CRITICAL, anomalies.get(0).getSeverity());
        assertTrue(anomalies.get(0).getRuleTriggered().contains("Blacklisted IP"));
    }

    @Test
    @DisplayName("Verify off-hours access detection (03:00 AM)")
    void testOffHoursAccess() {
        List<LogEntry> entries = List.of(
                new LogEntry(1, "2026-09-16 03:15:00", "nightuser", "SUCCESS_LOGIN", "192.168.1.50", "raw")
        );

        List<Anomaly> anomalies = analyzer.evaluate(entries, testScanId);
        assertTrue(anomalies.stream().anyMatch(a -> a.getSeverity() == Anomaly.Severity.MEDIUM && a.getRuleTriggered().contains("Off-Hours")));
    }

    @Test
    @DisplayName("Verify suspicious account probe detection")
    void testSuspiciousAccountProbe() {
        List<LogEntry> entries = List.of(
                new LogEntry(1, "2026-09-16 11:00:00", "root", "FAILED_LOGIN", "192.168.1.77", "raw")
        );

        List<Anomaly> anomalies = analyzer.evaluate(entries, testScanId);
        assertTrue(anomalies.stream().anyMatch(a -> a.getSeverity() == Anomaly.Severity.HIGH && a.getRuleTriggered().contains("Suspicious Account Probe")));
    }
}
