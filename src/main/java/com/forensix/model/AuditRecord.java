package com.forensix.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a tamper-evident audit record in the hash chain.
 * Each record cryptographically seals its canonical data and the previous record's hash.
 */
public class AuditRecord {

    public static final String GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    public enum RecordType {
        FILE_EVENT,
        ANOMALY,
        SCAN,
        BASELINE,
        SYSTEM
    }

    private long id;
    private RecordType recordType;
    private long recordRefId;
    private String payload;
    private String prevHash;
    private String recordHash;
    private String createdAt;

    public AuditRecord() {
        this.createdAt = Instant.now().toString();
    }

    public AuditRecord(RecordType recordType, long recordRefId, String payload, String prevHash, String recordHash) {
        this.recordType = recordType;
        this.recordRefId = recordRefId;
        this.payload = payload;
        this.prevHash = prevHash;
        this.recordHash = recordHash;
        this.createdAt = Instant.now().toString();
    }

    public AuditRecord(long id, RecordType recordType, long recordRefId, String payload, String prevHash, String recordHash, String createdAt) {
        this.id = id;
        this.recordType = recordType;
        this.recordRefId = recordRefId;
        this.payload = payload;
        this.prevHash = prevHash;
        this.recordHash = recordHash;
        this.createdAt = createdAt;
    }

    /**
     * Produces the strict, deterministic canonical string representation of this audit record's content.
     * This is the exact string combined with prevHash to compute recordHash:
     * canonicalData = recordType|recordRefId|payload|createdAt
     */
    public String getCanonicalData() {
        String safePayload = (payload != null) ? payload : "";
        String safeCreatedAt = (createdAt != null) ? createdAt : "";
        String safeType = (recordType != null) ? recordType.name() : "";
        return safeType + "|" + recordRefId + "|" + safePayload + "|" + safeCreatedAt;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public RecordType getRecordType() { return recordType; }
    public void setRecordType(RecordType recordType) { this.recordType = recordType; }

    public long getRecordRefId() { return recordRefId; }
    public void setRecordRefId(long recordRefId) { this.recordRefId = recordRefId; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public String getPrevHash() { return prevHash; }
    public void setPrevHash(String prevHash) { this.prevHash = prevHash; }

    public String getRecordHash() { return recordHash; }
    public void setRecordHash(String recordHash) { this.recordHash = recordHash; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditRecord that = (AuditRecord) o;
        return id == that.id && Objects.equals(recordHash, that.recordHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, recordHash);
    }

    @Override
    public String toString() {
        return "AuditRecord{" +
                "id=" + id +
                ", type=" + recordType +
                ", refId=" + recordRefId +
                ", prevHash='" + (prevHash != null && prevHash.length() > 8 ? prevHash.substring(0, 8) + "..." : prevHash) + '\'' +
                ", recordHash='" + (recordHash != null && recordHash.length() > 8 ? recordHash.substring(0, 8) + "..." : recordHash) + '\'' +
                ", createdAt='" + createdAt + '\'' +
                '}';
    }
}
