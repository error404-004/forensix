package com.forensix.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a scan execution session.
 */
public class Scan {
    private long id;
    private String startedAt;
    private String finishedAt;
    private String status; // IN_PROGRESS, COMPLETED, FAILED
    private String scannedDirectory;

    private List<FileEvent> events = new ArrayList<>();
    private List<Anomaly> anomalies = new ArrayList<>();

    public Scan() {
        this.startedAt = Instant.now().toString();
        this.status = "IN_PROGRESS";
    }

    public Scan(long id, String startedAt, String finishedAt, String status) {
        this.id = id;
        this.startedAt = startedAt;
        this.finishedAt = finishedAt;
        this.status = status;
    }

    public Scan(long id, String startedAt, String finishedAt, String status, String scannedDirectory) {
        this(id, startedAt, finishedAt, status);
        this.scannedDirectory = scannedDirectory;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public String getStartedAt() { return startedAt; }
    public void setStartedAt(String startedAt) { this.startedAt = startedAt; }

    public String getFinishedAt() { return finishedAt; }
    public void setFinishedAt(String finishedAt) { this.finishedAt = finishedAt; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getScannedDirectory() { return scannedDirectory; }
    public void setScannedDirectory(String scannedDirectory) { this.scannedDirectory = scannedDirectory; }

    public List<FileEvent> getEvents() { return events; }
    public void setEvents(List<FileEvent> events) { this.events = events; }

    public List<Anomaly> getAnomalies() { return anomalies; }
    public void setAnomalies(List<Anomaly> anomalies) { this.anomalies = anomalies; }

    public long getAddedCount() {
        return events.stream().filter(e -> e.getEventType() == FileEvent.EventType.ADDED).count();
    }

    public long getModifiedCount() {
        return events.stream().filter(e -> e.getEventType() == FileEvent.EventType.MODIFIED).count();
    }

    public long getDeletedCount() {
        return events.stream().filter(e -> e.getEventType() == FileEvent.EventType.DELETED).count();
    }

    public long getUnchangedCount() {
        return events.stream().filter(e -> e.getEventType() == FileEvent.EventType.UNCHANGED).count();
    }

    public long getErrorCount() {
        return events.stream().filter(e -> e.getEventType() == FileEvent.EventType.SCAN_ERROR).count();
    }

    @Override
    public String toString() {
        return "Scan{" +
                "id=" + id +
                ", startedAt='" + startedAt + '\'' +
                ", finishedAt='" + finishedAt + '\'' +
                ", status='" + status + '\'' +
                ", events=" + events.size() +
                ", anomalies=" + anomalies.size() +
                '}';
    }
}
