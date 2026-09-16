package com.forensix.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a security anomaly detected by log analysis rules.
 */
public class Anomaly {

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    private long id;
    private long scanId;
    private String logEntry;
    private String ruleTriggered;
    private Severity severity;
    private String detectedAt;

    public Anomaly() {
        this.detectedAt = Instant.now().toString();
    }

    public Anomaly(long scanId, String logEntry, String ruleTriggered, Severity severity) {
        this.scanId = scanId;
        this.logEntry = logEntry;
        this.ruleTriggered = ruleTriggered;
        this.severity = severity;
        this.detectedAt = Instant.now().toString();
    }

    public Anomaly(long id, long scanId, String logEntry, String ruleTriggered, Severity severity, String detectedAt) {
        this.id = id;
        this.scanId = scanId;
        this.logEntry = logEntry;
        this.ruleTriggered = ruleTriggered;
        this.severity = severity;
        this.detectedAt = detectedAt;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getScanId() { return scanId; }
    public void setScanId(long scanId) { this.scanId = scanId; }

    public String getLogEntry() { return logEntry; }
    public void setLogEntry(String logEntry) { this.logEntry = logEntry; }

    public String getRuleTriggered() { return ruleTriggered; }
    public void setRuleTriggered(String ruleTriggered) { this.ruleTriggered = ruleTriggered; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public String getDetectedAt() { return detectedAt; }
    public void setDetectedAt(String detectedAt) { this.detectedAt = detectedAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Anomaly anomaly = (Anomaly) o;
        return scanId == anomaly.scanId &&
                Objects.equals(logEntry, anomaly.logEntry) &&
                Objects.equals(ruleTriggered, anomaly.ruleTriggered) &&
                severity == anomaly.severity;
    }

    @Override
    public int hashCode() {
        return Objects.hash(scanId, logEntry, ruleTriggered, severity);
    }

    @Override
    public String toString() {
        return "Anomaly{" +
                "id=" + id +
                ", scanId=" + scanId +
                ", ruleTriggered='" + ruleTriggered + '\'' +
                ", severity=" + severity +
                ", logEntry='" + logEntry + '\'' +
                ", detectedAt='" + detectedAt + '\'' +
                '}';
    }
}
