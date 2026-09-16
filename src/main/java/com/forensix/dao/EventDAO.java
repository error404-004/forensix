package com.forensix.dao;

import com.forensix.model.FileEvent;

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
 * Data Access Object for file integrity events detected during scans.
 */
public class EventDAO {
    private static final Logger LOGGER = Logger.getLogger(EventDAO.class.getName());
    private final DatabaseManager dbManager;

    public EventDAO(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    public long insert(FileEvent event) {
        String sql = """
            INSERT INTO file_events (scan_id, path, event_type, old_hash, new_hash, detected_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, event.getScanId());
            ps.setString(2, event.getPath());
            ps.setString(3, event.getEventType().name());
            ps.setString(4, event.getOldHash());
            ps.setString(5, event.getNewHash());
            ps.setString(6, event.getDetectedAt());
            ps.setString(7, event.getErrorMessage());
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    long id = rs.getLong(1);
                    event.setId(id);
                    return id;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting file event: " + event.getPath(), e);
            throw new RuntimeException("Database error saving file event", e);
        }
        return -1;
    }

    public void insertBatch(List<FileEvent> events) {
        if (events == null || events.isEmpty()) return;

        String sql = """
            INSERT INTO file_events (scan_id, path, event_type, old_hash, new_hash, detected_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                for (FileEvent event : events) {
                    ps.setLong(1, event.getScanId());
                    ps.setString(2, event.getPath());
                    ps.setString(3, event.getEventType().name());
                    ps.setString(4, event.getOldHash());
                    ps.setString(5, event.getNewHash());
                    ps.setString(6, event.getDetectedAt());
                    ps.setString(7, event.getErrorMessage());
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                LOGGER.log(Level.SEVERE, "Error during batch insert of file events, rolled back", e);
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Batch insert failed for file events", e);
        }
    }

    public List<FileEvent> findByScanId(long scanId) {
        List<FileEvent> list = new ArrayList<>();
        String sql = """
            SELECT id, scan_id, path, event_type, old_hash, new_hash, detected_at, error_message
            FROM file_events WHERE scan_id = ? ORDER BY id ASC;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, scanId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    FileEvent event = new FileEvent(
                            rs.getLong("id"),
                            rs.getLong("scan_id"),
                            rs.getString("path"),
                            FileEvent.EventType.valueOf(rs.getString("event_type")),
                            rs.getString("old_hash"),
                            rs.getString("new_hash"),
                            rs.getString("detected_at")
                    );
                    event.setErrorMessage(rs.getString("error_message"));
                    list.add(event);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error querying file events for scan " + scanId, e);
            throw new RuntimeException("Database error fetching file events", e);
        }
        return list;
    }

    public List<FileEvent> findAll() {
        List<FileEvent> list = new ArrayList<>();
        String sql = """
            SELECT id, scan_id, path, event_type, old_hash, new_hash, detected_at, error_message
            FROM file_events ORDER BY id DESC;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                FileEvent event = new FileEvent(
                        rs.getLong("id"),
                        rs.getLong("scan_id"),
                        rs.getString("path"),
                        FileEvent.EventType.valueOf(rs.getString("event_type")),
                        rs.getString("old_hash"),
                        rs.getString("new_hash"),
                        rs.getString("detected_at")
                );
                event.setErrorMessage(rs.getString("error_message"));
                list.add(event);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error querying all file events", e);
            throw new RuntimeException("Database error fetching all file events", e);
        }
        return list;
    }
}
