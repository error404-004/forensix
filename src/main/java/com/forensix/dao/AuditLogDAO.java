package com.forensix.dao;

import com.forensix.model.AuditRecord;

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
 * Data Access Object for the tamper-evident audit log.
 *
 * <p>CRITICAL SECURITY REQUIREMENT:
 * This DAO implements an APPLICATION-LEVEL APPEND-ONLY policy.
 * It provides methods only to append new records (insert) and read existing records.
 * Absolutely NO update, delete, or truncate operations are exposed here.</p>
 */
public class AuditLogDAO {
    private static final Logger LOGGER = Logger.getLogger(AuditLogDAO.class.getName());
    private final DatabaseManager dbManager;

    public AuditLogDAO(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    /**
     * Appends a new audit record to the tamper-evident chain.
     */
    public synchronized long insert(AuditRecord record) {
        String sql = """
            INSERT INTO audit_log (record_type, record_ref_id, payload, prev_hash, record_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, record.getRecordType().name());
            ps.setLong(2, record.getRecordRefId());
            ps.setString(3, record.getPayload());
            ps.setString(4, record.getPrevHash());
            ps.setString(5, record.getRecordHash());
            ps.setString(6, record.getCreatedAt());
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    long id = rs.getLong(1);
                    record.setId(id);
                    return id;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Failed to insert audit record: " + record.getRecordType(), e);
            throw new RuntimeException("Critical failure appending to audit log", e);
        }
        throw new RuntimeException("Failed to retrieve generated audit log record ID");
    }

    /**
     * Retrieves the most recent audit record in the chain (highest ID).
     * Used to establish the prev_hash for the next appended record.
     */
    public synchronized AuditRecord getLastRecord() {
        String sql = """
            SELECT id, record_type, record_ref_id, payload, prev_hash, record_hash, created_at
            FROM audit_log ORDER BY id DESC LIMIT 1;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return mapResultSetToAuditRecord(rs);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error fetching last audit record", e);
            throw new RuntimeException("Database error retrieving last audit record", e);
        }
        return null;
    }

    /**
     * Retrieves all audit records in strict deterministic ascending ID order.
     * This order is required for verifying the cryptographic hash chain.
     */
    public List<AuditRecord> findAllOrderedById() {
        List<AuditRecord> list = new ArrayList<>();
        String sql = """
            SELECT id, record_type, record_ref_id, payload, prev_hash, record_hash, created_at
            FROM audit_log ORDER BY id ASC;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                list.add(mapResultSetToAuditRecord(rs));
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error fetching all audit records in verification order", e);
            throw new RuntimeException("Database error retrieving audit trail", e);
        }
        return list;
    }

    public AuditRecord findById(long id) {
        String sql = """
            SELECT id, record_type, record_ref_id, payload, prev_hash, record_hash, created_at
            FROM audit_log WHERE id = ?;
            """;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToAuditRecord(rs);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error fetching audit record with id: " + id, e);
            throw new RuntimeException("Database error retrieving audit record", e);
        }
        return null;
    }

    public int count() {
        String sql = "SELECT COUNT(*) FROM audit_log;";
        try (Connection conn = dbManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error counting audit log records", e);
            throw new RuntimeException("Database error counting audit records", e);
        }
        return 0;
    }

    private AuditRecord mapResultSetToAuditRecord(ResultSet rs) throws SQLException {
        return new AuditRecord(
                rs.getLong("id"),
                AuditRecord.RecordType.valueOf(rs.getString("record_type")),
                rs.getLong("record_ref_id"),
                rs.getString("payload"),
                rs.getString("prev_hash"),
                rs.getString("record_hash"),
                rs.getString("created_at")
        );
    }
}
