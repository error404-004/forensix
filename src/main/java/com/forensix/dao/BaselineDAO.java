package com.forensix.dao;

import com.forensix.model.FileRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data Access Object for baseline file records.
 * Uses 100% parameterized PreparedStatements.
 */
public class BaselineDAO {
    private static final Logger LOGGER = Logger.getLogger(BaselineDAO.class.getName());
    private final DatabaseManager dbManager;

    public BaselineDAO(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    public void insert(FileRecord record) {
        String sql = """
            INSERT OR REPLACE INTO baseline_files (path, hash, size_bytes, last_modified, created_at)
            VALUES (?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.getPath());
            ps.setString(2, record.getHash());
            ps.setLong(3, record.getSizeBytes());
            ps.setString(4, record.getLastModified());
            ps.setString(5, record.getCreatedAt());
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting baseline file: " + record.getPath(), e);
            throw new RuntimeException("Database error saving baseline file", e);
        }
    }

    public void insertBatch(List<FileRecord> records) {
        if (records == null || records.isEmpty()) return;

        String sql = """
            INSERT OR REPLACE INTO baseline_files (path, hash, size_bytes, last_modified, created_at)
            VALUES (?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                for (FileRecord record : records) {
                    ps.setString(1, record.getPath());
                    ps.setString(2, record.getHash());
                    ps.setLong(3, record.getSizeBytes());
                    ps.setString(4, record.getLastModified());
                    ps.setString(5, record.getCreatedAt());
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                LOGGER.log(Level.SEVERE, "Rolled back baseline batch insert due to error", e);
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Batch insert failed for baseline files", e);
        }
    }

    public List<FileRecord> findAll() {
        List<FileRecord> list = new ArrayList<>();
        String sql = "SELECT id, path, hash, size_bytes, last_modified, created_at FROM baseline_files ORDER BY path ASC;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                FileRecord record = new FileRecord(
                        rs.getLong("id"),
                        rs.getString("path"),
                        rs.getString("hash"),
                        rs.getLong("size_bytes"),
                        rs.getString("last_modified"),
                        rs.getString("created_at")
                );
                list.add(record);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error querying baseline files", e);
            throw new RuntimeException("Database error fetching baseline files", e);
        }
        return list;
    }

    public FileRecord findByPath(String path) {
        String sql = "SELECT id, path, hash, size_bytes, last_modified, created_at FROM baseline_files WHERE path = ?;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, path);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new FileRecord(
                            rs.getLong("id"),
                            rs.getString("path"),
                            rs.getString("hash"),
                            rs.getLong("size_bytes"),
                            rs.getString("last_modified"),
                            rs.getString("created_at")
                    );
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error finding baseline by path: " + path, e);
            throw new RuntimeException("Database error fetching baseline record", e);
        }
        return null;
    }

    public void clear() {
        String sql = "DELETE FROM baseline_files;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error clearing baseline", e);
            throw new RuntimeException("Database error clearing baseline", e);
        }
    }

    public int count() {
        String sql = "SELECT COUNT(*) FROM baseline_files;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error counting baseline files", e);
            throw new RuntimeException("Database error counting baseline records", e);
        }
        return 0;
    }
}
