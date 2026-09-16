package com.forensix.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents an integrity event detected when scanning files against the baseline.
 */
public class FileEvent {

    public enum EventType {
        ADDED,
        MODIFIED,
        DELETED,
        UNCHANGED,
        SCAN_ERROR
    }

    private long id;
    private long scanId;
    private String path;
    private EventType eventType;
    private String oldHash;
    private String newHash;
    private String detectedAt;
    private String errorMessage;

    public FileEvent() {
        this.detectedAt = Instant.now().toString();
    }

    public FileEvent(long scanId, String path, EventType eventType, String oldHash, String newHash) {
        this.scanId = scanId;
        this.path = path;
        this.eventType = eventType;
        this.oldHash = oldHash;
        this.newHash = newHash;
        this.detectedAt = Instant.now().toString();
    }

    public FileEvent(long scanId, String path, EventType eventType, String oldHash, String newHash, String errorMessage) {
        this(scanId, path, eventType, oldHash, newHash);
        this.errorMessage = errorMessage;
    }

    public FileEvent(long id, long scanId, String path, EventType eventType, String oldHash, String newHash, String detectedAt) {
        this.id = id;
        this.scanId = scanId;
        this.path = path;
        this.eventType = eventType;
        this.oldHash = oldHash;
        this.newHash = newHash;
        this.detectedAt = detectedAt;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getScanId() { return scanId; }
    public void setScanId(long scanId) { this.scanId = scanId; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public EventType getEventType() { return eventType; }
    public void setEventType(EventType eventType) { this.eventType = eventType; }

    public String getOldHash() { return oldHash; }
    public void setOldHash(String oldHash) { this.oldHash = oldHash; }

    public String getNewHash() { return newHash; }
    public void setNewHash(String newHash) { this.newHash = newHash; }

    public String getDetectedAt() { return detectedAt; }
    public void setDetectedAt(String detectedAt) { this.detectedAt = detectedAt; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FileEvent fileEvent = (FileEvent) o;
        return scanId == fileEvent.scanId && Objects.equals(path, fileEvent.path) && eventType == fileEvent.eventType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(scanId, path, eventType);
    }

    @Override
    public String toString() {
        return "FileEvent{" +
                "id=" + id +
                ", scanId=" + scanId +
                ", path='" + path + '\'' +
                ", eventType=" + eventType +
                ", oldHash='" + oldHash + '\'' +
                ", newHash='" + newHash + '\'' +
                ", detectedAt='" + detectedAt + '\'' +
                '}';
    }
}
