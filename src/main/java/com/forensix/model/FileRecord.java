package com.forensix.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a baselined file record stored in the database.
 */
public class FileRecord {
    private long id;
    private String path;
    private String hash;
    private long sizeBytes;
    private String lastModified;
    private String createdAt;

    public FileRecord() {
        this.createdAt = Instant.now().toString();
    }

    public FileRecord(String path, String hash, long sizeBytes, String lastModified) {
        this.path = path;
        this.hash = hash;
        this.sizeBytes = sizeBytes;
        this.lastModified = lastModified;
        this.createdAt = Instant.now().toString();
    }

    public FileRecord(long id, String path, String hash, long sizeBytes, String lastModified, String createdAt) {
        this.id = id;
        this.path = path;
        this.hash = hash;
        this.sizeBytes = sizeBytes;
        this.lastModified = lastModified;
        this.createdAt = createdAt;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getHash() { return hash; }
    public void setHash(String hash) { this.hash = hash; }

    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long sizeBytes) { this.sizeBytes = sizeBytes; }

    public String getLastModified() { return lastModified; }
    public void setLastModified(String lastModified) { this.lastModified = lastModified; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FileRecord that = (FileRecord) o;
        return Objects.equals(path, that.path) && Objects.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, hash);
    }

    @Override
    public String toString() {
        return "FileRecord{" +
                "id=" + id +
                ", path='" + path + '\'' +
                ", hash='" + hash + '\'' +
                ", sizeBytes=" + sizeBytes +
                ", lastModified='" + lastModified + '\'' +
                ", createdAt='" + createdAt + '\'' +
                '}';
    }
}
