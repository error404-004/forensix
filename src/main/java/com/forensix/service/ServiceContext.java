package com.forensix.service;

import com.forensix.dao.AnomalyDAO;
import com.forensix.dao.AuditLogDAO;
import com.forensix.dao.BaselineDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.dao.EventDAO;
import com.forensix.dao.ScanDAO;
import com.forensix.model.Anomaly;
import com.forensix.model.AuditRecord;
import com.forensix.model.Config;
import com.forensix.model.FileEvent;
import com.forensix.model.FileRecord;
import com.forensix.model.LogEntry;
import com.forensix.model.Scan;
import com.forensix.util.ConfigLoader;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Central service container connecting DAOs, business services, and scheduler.
 */
public class ServiceContext {
    private static final Logger LOGGER = Logger.getLogger(ServiceContext.class.getName());

    private final ConfigLoader configLoader;
    private Config config;

    private final DatabaseManager dbManager;
    private final BaselineDAO baselineDAO;
    private final ScanDAO scanDAO;
    private final EventDAO eventDAO;
    private final AnomalyDAO anomalyDAO;
    private final AuditLogDAO auditLogDAO;

    private final IntegrityScanner integrityScanner;
    private final LogAnalyzer logAnalyzer;
    private final AuditService auditService;
    private final ReportGenerator reportGenerator;
    private final ScanScheduler scanScheduler;

    public ServiceContext() {
        this(null);
    }

    public ServiceContext(String customDbPath) {
        this.configLoader = new ConfigLoader();
        this.config = configLoader.loadConfig();
        if (customDbPath != null && !customDbPath.isBlank()) {
            this.config.setDatabasePath(customDbPath);
        }

        this.dbManager = new DatabaseManager(config.getDatabasePath());
        this.dbManager.initSchema();

        this.baselineDAO = new BaselineDAO(dbManager);
        this.scanDAO = new ScanDAO(dbManager);
        this.eventDAO = new EventDAO(dbManager);
        this.anomalyDAO = new AnomalyDAO(dbManager);
        this.auditLogDAO = new AuditLogDAO(dbManager);

        this.integrityScanner = new IntegrityScannerImpl(baselineDAO, eventDAO);

        LogAnalyzerImpl analyzerImpl = new LogAnalyzerImpl(anomalyDAO);
        analyzerImpl.setFailedLoginThreshold(config.getFailedLoginThreshold());
        analyzerImpl.setTimeWindowMinutes(config.getTimeWindowMinutes());
        analyzerImpl.setBusinessHours(config.getParsedBusinessStart(), config.getParsedBusinessEnd());
        analyzerImpl.setBlacklistedIps(config.getBlacklistedIpsSet());
        analyzerImpl.setSuspiciousUsers(config.getSuspiciousUsersSet());
        this.logAnalyzer = analyzerImpl;

        this.auditService = new AuditServiceImpl(auditLogDAO);
        this.reportGenerator = new ReportGenerator(scanDAO, eventDAO, anomalyDAO, auditService, config.getReportsDirectory());
        this.scanScheduler = new ScanScheduler();

        // If audit log is brand new, write initial genesis system record
        if (auditService.getRecordCount() == 0) {
            auditService.record(AuditRecord.RecordType.SYSTEM, 0, "FORENSIX Toolkit Initialized");
        }
    }

    /**
     * Executes the complete end-to-end audit workflow:
     * Scan filesystem -> Diff baseline -> Parse logs -> Evaluate rules ->
     * Hash-chain audit findings -> Generate report.
     */
    public synchronized Scan executeFullScan(Path monitoredDir, Path logFilePath) {
        LOGGER.info("Executing comprehensive security audit scan...");
        long scanId = scanDAO.createScan(monitoredDir.toString());

        auditService.record(AuditRecord.RecordType.SCAN, scanId, "SCAN_STARTED: " + monitoredDir);

        Scan scan = scanDAO.findById(scanId);

        try {
            // 1. File Integrity Scan
            List<FileEvent> events = integrityScanner.scan(monitoredDir, scanId);
            scan.setEvents(events);

            for (FileEvent event : events) {
                if (event.getEventType() != FileEvent.EventType.UNCHANGED) {
                    auditService.record(
                            AuditRecord.RecordType.FILE_EVENT,
                            event.getId(),
                            event.getEventType() + " | " + event.getPath() + " | " + event.getNewHash()
                    );
                }
            }

            // 2. Log Analysis
            if (logFilePath != null && java.nio.file.Files.exists(logFilePath)) {
                List<LogEntry> entries = logAnalyzer.parse(logFilePath);
                List<Anomaly> anomalies = logAnalyzer.evaluate(entries, scanId);
                scan.setAnomalies(anomalies);

                for (Anomaly anomaly : anomalies) {
                    auditService.record(
                            AuditRecord.RecordType.ANOMALY,
                            anomaly.getId(),
                            anomaly.getSeverity() + " | " + anomaly.getRuleTriggered() + " | " + anomaly.getLogEntry()
                    );
                }
            }

            // 3. Mark Scan Completed
            scanDAO.updateScanStatus(scanId, "COMPLETED", Instant.now().toString());
            scan.setStatus("COMPLETED");
            scan.setFinishedAt(Instant.now().toString());

            auditService.record(
                    AuditRecord.RecordType.SCAN,
                    scanId,
                    "SCAN_COMPLETED: " + events.size() + " files checked, " + scan.getAnomalies().size() + " anomalies detected."
            );

            // 4. Generate Report
            reportGenerator.generateReport(scanId);

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Scan execution encountered critical failure", e);
            scanDAO.updateScanStatus(scanId, "FAILED", Instant.now().toString());
            scan.setStatus("FAILED");
            auditService.record(AuditRecord.RecordType.SCAN, scanId, "SCAN_FAILED: " + e.getMessage());
            throw new RuntimeException("Security scan failed: " + e.getMessage(), e);
        }

        return scan;
    }

    /**
     * Creates a new baseline and records it in the audit trail.
     */
    public synchronized List<FileRecord> createBaseline(Path monitoredDir) {
        List<FileRecord> records = integrityScanner.createBaseline(monitoredDir);
        auditService.record(
                AuditRecord.RecordType.BASELINE,
                records.size(),
                "BASELINE_ESTABLISHED: " + records.size() + " files recorded for " + monitoredDir
        );
        return records;
    }

    public Config getConfig() { return config; }
    public void setConfig(Config config) { this.config = config; }
    public ConfigLoader getConfigLoader() { return configLoader; }
    public DatabaseManager getDbManager() { return dbManager; }
    public BaselineDAO getBaselineDAO() { return baselineDAO; }
    public ScanDAO getScanDAO() { return scanDAO; }
    public EventDAO getEventDAO() { return eventDAO; }
    public AnomalyDAO getAnomalyDAO() { return anomalyDAO; }
    public AuditLogDAO getAuditLogDAO() { return auditLogDAO; }
    public IntegrityScanner getIntegrityScanner() { return integrityScanner; }
    public LogAnalyzer getLogAnalyzer() { return logAnalyzer; }
    public AuditService getAuditService() { return auditService; }
    public ReportGenerator getReportGenerator() { return reportGenerator; }
    public ScanScheduler getScanScheduler() { return scanScheduler; }
}
