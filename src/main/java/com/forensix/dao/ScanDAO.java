package com.forensix.dao;

import com.forensix.model.Scan;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data Access Object for scan sessions.
 */
public class ScanDAO {
    private static final Logger LOGGER = Logger.getLogger(ScanDAO.class.getName());
    private final DatabaseManager dbManager;

    public ScanDAO(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    public long createScan(String scannedDirectory) {
        String sql = "INSERT INTO scans (started_at, status, scanned_directory) VALUES (?, ?, ?);";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, Instant.now().toString());
            ps.setString(2, "IN_PROGRESS");
            ps.setString(3, scannedDirectory != null ? scannedDirectory : "");
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error creating scan session", e);
            throw new RuntimeException("Database error creating scan session", e);
        }
        throw new RuntimeException("Failed to retrieve generated scan ID");
    }

    public void updateScanStatus(long scanId, String status, String finishedAt) {
        String sql = "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, finishedAt != null ? finishedAt : Instant.now().toString());
            ps.setLong(3, scanId);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error updating scan status for scan " + scanId, e);
            throw new RuntimeException("Database error updating scan status", e);
        }
    }

    public Scan findById(long scanId) {
        String sql = "SELECT id, started_at, finished_at, status, scanned_directory FROM scans WHERE id = ?;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, scanId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new Scan(
                            rs.getLong("id"),
                            rs.getString("started_at"),
                            rs.getString("finished_at"),
                            rs.getString("status"),
                            rs.getString("scanned_directory")
                    );
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error fetching scan by id: " + scanId, e);
            throw new RuntimeException("Database error fetching scan", e);
        }
        return null;
    }

    public Scan getLastScan() {
        String sql = "SELECT id, started_at, finished_at, status, scanned_directory FROM scans ORDER BY id DESC LIMIT 1;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return new Scan(
                        rs.getLong("id"),
                        rs.getString("started_at"),
                        rs.getString("finished_at"),
                        rs.getString("status"),
                        rs.getString("scanned_directory")
                );
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error fetching last scan", e);
            throw new RuntimeException("Database error fetching last scan", e);
        }
        return null;
    }

    public List<Scan> findAllOrderedByIdDesc() {
        List<Scan> list = new ArrayList<>();
        String sql = "SELECT id, started_at, finished_at, status, scanned_directory FROM scans ORDER BY id DESC;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                list.add(new Scan(
                        rs.getLong("id"),
                        rs.getString("started_at"),
                        rs.getString("finished_at"),
                        rs.getString("status"),
                        rs.getString("scanned_directory")
                ));
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error fetching all scans", e);
            throw new RuntimeException("Database error fetching scan history", e);
        }
        return list;
    }
}
