package com.forensix.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Objects;

/**
 * Represents a parsed system or authentication log entry.
 */
public class LogEntry {
    private static final DateTimeFormatter FORMATTER_SPACE = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FORMATTER_T = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    private int lineNumber;
    private String timestamp;
    private String user;
    private String event;
    private String ip;
    private String rawLine;

    public LogEntry() {}

    public LogEntry(int lineNumber, String timestamp, String user, String event, String ip, String rawLine) {
        this.lineNumber = lineNumber;
        this.timestamp = timestamp;
        this.user = user;
        this.event = event;
        this.ip = ip;
        this.rawLine = rawLine;
    }

    public int getLineNumber() { return lineNumber; }
    public void setLineNumber(int lineNumber) { this.lineNumber = lineNumber; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getEvent() { return event; }
    public void setEvent(String event) { this.event = event; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getRawLine() { return rawLine; }
    public void setRawLine(String rawLine) { this.rawLine = rawLine; }

    /**
     * Parses the entry's timestamp into a LocalDateTime.
     * Returns null if unparseable.
     */
    public LocalDateTime getParsedDateTime() {
        if (timestamp == null || timestamp.isBlank()) return null;
        try {
            if (timestamp.contains("T")) {
                return LocalDateTime.parse(timestamp.trim(), FORMATTER_T);
            }
            return LocalDateTime.parse(timestamp.trim(), FORMATTER_SPACE);
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(timestamp.trim());
            } catch (Exception ex) {
                return null;
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LogEntry logEntry = (LogEntry) o;
        return lineNumber == logEntry.lineNumber && Objects.equals(rawLine, logEntry.rawLine);
    }

    @Override
    public int hashCode() {
        return Objects.hash(lineNumber, rawLine);
    }

    @Override
    public String toString() {
        return "LogEntry{" +
                "line=" + lineNumber +
                ", time='" + timestamp + '\'' +
                ", user='" + user + '\'' +
                ", event='" + event + '\'' +
                ", ip='" + ip + '\'' +
                '}';
    }
}
