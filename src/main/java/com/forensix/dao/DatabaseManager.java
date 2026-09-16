package com.forensix.dao;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages SQLite database connections and schema bootstrapping.
 * Supports production disk database and isolated in-memory or custom database paths for testing.
 */
public class DatabaseManager {
    private static final Logger LOGGER = Logger.getLogger(DatabaseManager.class.getName());
    public static final String DEFAULT_DB_PATH = "data/forensix.db";

    private final String dbPath;

    public DatabaseManager() {
        this(DEFAULT_DB_PATH);
    }

    public DatabaseManager(String dbPath) {
        this.dbPath = dbPath;
        ensureDirectoryExists();
    }

    private void ensureDirectoryExists() {
        if (dbPath != null && !dbPath.startsWith(":memory:") && !dbPath.contains("mode=memory")) {
            File dbFile = new File(dbPath);
            File parentDir = dbFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
        }
    }

    public String getDbPath() {
        return dbPath;
    }

    /**
     * Obtains a new database connection.
     */
    public Connection getConnection() throws SQLException {
        String url = "jdbc:sqlite:" + dbPath;
        Connection conn = DriverManager.getConnection(url);
        // Enforce foreign key constraints in SQLite
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON;");
        }
        return conn;
    }

    /**
     * Initializes all schema tables and indexes if they do not already exist.
     */
    public void initSchema() {
        LOGGER.info("Initializing SQLite database schema at: " + dbPath);

        String createBaselineFiles = """
            CREATE TABLE IF NOT EXISTS baseline_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                hash TEXT NOT NULL,
                size_bytes INTEGER,
                last_modified TEXT,
                created_at TEXT NOT NULL
            );
            """;

        String createScans = """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                scanned_directory TEXT
            );
            """;

        String createFileEvents = """
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                detected_at TEXT NOT NULL,
                error_message TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """;

        String createAnomalies = """
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                log_entry TEXT NOT NULL,
                rule_triggered TEXT NOT NULL,
                severity TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """;

        // Append-only audit log table: stores hash-chained records
        String createAuditLog = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_type TEXT NOT NULL,
                record_ref_id INTEGER,
                payload TEXT,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """;

        String createIndexes = """
            CREATE INDEX IF NOT EXISTS idx_baseline_path ON baseline_files(path);
            CREATE INDEX IF NOT EXISTS idx_events_scan ON file_events(scan_id);
            CREATE INDEX IF NOT EXISTS idx_anomalies_scan ON anomalies(scan_id);
            CREATE INDEX IF NOT EXISTS idx_audit_order ON audit_log(id);
            """;

        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(createBaselineFiles);
            stmt.execute(createScans);
            stmt.execute(createFileEvents);
            stmt.execute(createAnomalies);
            stmt.execute(createAuditLog);
            stmt.execute(createIndexes);
            LOGGER.info("Database schema initialized successfully.");
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Failed to initialize database schema: " + e.getMessage(), e);
            throw new RuntimeException("Database initialization failure", e);
        }
    }
}
