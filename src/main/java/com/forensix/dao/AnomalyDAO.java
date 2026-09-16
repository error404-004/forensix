package com.forensix.dao;

import com.forensix.model.Anomaly;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data Access Object for security anomalies flagged by the log analyzer.
 */
public class AnomalyDAO {
    private static final Logger LOGGER = Logger.getLogger(AnomalyDAO.class.getName());
    private final DatabaseManager dbManager;

    public AnomalyDAO(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    public long insert(Anomaly anomaly) {
        String sql = """
            INSERT INTO anomalies (scan_id, log_entry, rule_triggered, severity, detected_at)
            VALUES (?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, anomaly.getScanId());
            ps.setString(2, anomaly.getLogEntry());
            ps.setString(3, anomaly.getRuleTriggered());
            ps.setString(4, anomaly.getSeverity().name());
            ps.setString(5, anomaly.getDetectedAt());
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    long id = rs.getLong(1);
                    anomaly.setId(id);
                    return id;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting anomaly: " + anomaly.getRuleTriggered(), e);
            throw new RuntimeException("Database error saving anomaly", e);
        }
        return -1;
    }

    public void insertBatch(List<Anomaly> anomalies) {
        if (anomalies == null || anomalies.isEmpty()) return;

        String sql = """
            INSERT INTO anomalies (scan_id, log_entry, rule_triggered, severity, detected_at)
            VALUES (?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                for (Anomaly anomaly : anomalies) {
                    ps.setLong(1, anomaly.getScanId());
                    ps.setString(2, anomaly.getLogEntry());
                    ps.setString(3, anomaly.getRuleTriggered());
                    ps.setString(4, anomaly.getSeverity().name());
                    ps.setString(5, anomaly.getDetectedAt());
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                LOGGER.log(Level.SEVERE, "Error during batch insert of anomalies, rolled back", e);
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Batch insert failed for anomalies", e);
        }
    }

    public List<Anomaly> findByScanId(long scanId) {
        List<Anomaly> list = new ArrayList<>();
        String sql = """
            SELECT id, scan_id, log_entry, rule_triggered, severity, detected_at
            FROM anomalies WHERE scan_id = ? ORDER BY id ASC;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, scanId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new Anomaly(
                            rs.getLong("id"),
                            rs.getLong("scan_id"),
                            rs.getString("log_entry"),
                            rs.getString("rule_triggered"),
                            Anomaly.Severity.valueOf(rs.getString("severity")),
                            rs.getString("detected_at")
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error querying anomalies for scan " + scanId, e);
            throw new RuntimeException("Database error fetching anomalies", e);
        }
        return list;
    }

    public List<Anomaly> findAll() {
        List<Anomaly> list = new ArrayList<>();
        String sql = """
            SELECT id, scan_id, log_entry, rule_triggered, severity, detected_at
            FROM anomalies ORDER BY id DESC;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                list.add(new Anomaly(
                        rs.getLong("id"),
                        rs.getLong("scan_id"),
                        rs.getString("log_entry"),
                        rs.getString("rule_triggered"),
                        Anomaly.Severity.valueOf(rs.getString("severity")),
                        rs.getString("detected_at")
                ));
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error querying all anomalies", e);
            throw new RuntimeException("Database error fetching all anomalies", e);
        }
        return list;
    }
}
