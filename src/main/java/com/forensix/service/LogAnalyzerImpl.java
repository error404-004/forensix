package com.forensix.service;

import com.forensix.dao.AnomalyDAO;
import com.forensix.model.Anomaly;
import com.forensix.model.LogEntry;
import com.forensix.util.PathValidator;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Implementation of LogAnalyzer.
 * Provides resilient log parsing and evaluated detection for authentication threats.
 */
public class LogAnalyzerImpl implements LogAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(LogAnalyzerImpl.class.getName());

    // Safe bounded delimiter pattern to avoid ReDoS
    private static final Pattern PIPE_PATTERN = Pattern.compile("\\s*\\|\\s*");

    private final AnomalyDAO anomalyDAO;

    // Detection Rule Parameters
    private int failedLoginThreshold = 5;
    private int timeWindowMinutes = 5;
    private LocalTime businessHoursStart = LocalTime.of(8, 0);
    private LocalTime businessHoursEnd = LocalTime.of(19, 0);
    private Set<String> blacklistedIps = new HashSet<>(Arrays.asList("198.51.100.23", "203.0.113.88", "192.0.2.1"));
    private Set<String> suspiciousUsers = new HashSet<>(Arrays.asList("root", "admin", "guest", "oracle", "postgres", "test"));

    private int parseErrorsCount = 0;

    public LogAnalyzerImpl(AnomalyDAO anomalyDAO) {
        this.anomalyDAO = anomalyDAO;
    }

    public void setFailedLoginThreshold(int failedLoginThreshold) {
        this.failedLoginThreshold = failedLoginThreshold;
    }

    public void setTimeWindowMinutes(int timeWindowMinutes) {
        this.timeWindowMinutes = timeWindowMinutes;
    }

    public void setBusinessHours(LocalTime start, LocalTime end) {
        this.businessHoursStart = start;
        this.businessHoursEnd = end;
    }

    public void setBlacklistedIps(Set<String> blacklistedIps) {
        this.blacklistedIps = blacklistedIps != null ? new HashSet<>(blacklistedIps) : new HashSet<>();
    }

    public void setSuspiciousUsers(Set<String> suspiciousUsers) {
        this.suspiciousUsers = suspiciousUsers != null ? new HashSet<>(suspiciousUsers) : new HashSet<>();
    }

    @Override
    public int getParseErrorsCount() {
        return parseErrorsCount;
    }

    @Override
    public List<LogEntry> parse(Path logFilePath) {
        Path validatedPath = PathValidator.validateLogFile(logFilePath.toString());
        LOGGER.info("Parsing log file: " + validatedPath);

        List<LogEntry> entries = new ArrayList<>();
        parseErrorsCount = 0;

        try (BufferedReader reader = Files.newBufferedReader(validatedPath, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmed = line.trim();

                // Skip comments and empty lines
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }

                String[] parts = PIPE_PATTERN.split(trimmed);
                if (parts.length < 4) {
                    LOGGER.warning("Malformed log line at " + lineNumber + ": '" + trimmed + "' (expected 4 pipe-delimited fields)");
                    parseErrorsCount++;
                    continue;
                }

                String timestamp = parts[0].trim();
                String user = parts[1].trim();
                String event = parts[2].trim();
                String ip = parts[3].trim();

                // Basic validation of fields
                if (timestamp.isEmpty() || user.isEmpty() || event.isEmpty() || ip.isEmpty()) {
                    LOGGER.warning("Blank field in log line at " + lineNumber + ": '" + trimmed + "'");
                    parseErrorsCount++;
                    continue;
                }

                entries.add(new LogEntry(lineNumber, timestamp, user, event, ip, trimmed));
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to read log file: " + validatedPath, e);
            throw new RuntimeException("Log file read failure", e);
        }

        LOGGER.info("Parsed " + entries.size() + " log entries successfully (" + parseErrorsCount + " malformed lines skipped).");
        return entries;
    }

    @Override
    public List<Anomaly> evaluate(List<LogEntry> entries, long scanId) {
        LOGGER.info("Evaluating " + entries.size() + " log entries for anomalies (Scan #" + scanId + ")...");
        List<Anomaly> anomalies = new ArrayList<>();

        // Map for Rule 1: IP -> sliding window of failed login timestamps
        Map<String, Deque<LogEntry>> failedLoginsByIp = new HashMap<>();
        Set<String> alreadyFlaggedBurstIps = new HashSet<>();

        for (LogEntry entry : entries) {
            LocalDateTime entryTime = entry.getParsedDateTime();
            String user = entry.getUser();
            String event = entry.getEvent().toUpperCase();
            String ip = entry.getIp();

            // Rule 3: Threat Intelligence Blacklisted IP
            if (blacklistedIps.contains(ip)) {
                anomalies.add(new Anomaly(
                        scanId,
                        entry.getRawLine(),
                        "Blacklisted IP Access: Connection from known threat IP " + ip,
                        Anomaly.Severity.CRITICAL
                ));
            }

            // Rule 4: Suspicious / High-Privilege Account Probe
            if (suspiciousUsers.contains(user.toLowerCase()) && event.contains("FAIL")) {
                anomalies.add(new Anomaly(
                        scanId,
                        entry.getRawLine(),
                        "Suspicious Account Probe: Unauthorized access attempt against '" + user + "' from " + ip,
                        Anomaly.Severity.HIGH
                ));
            }

            // Rule 2: Off-Hours Access Detection
            if (entryTime != null) {
                LocalTime time = entryTime.toLocalTime();
                if (time.isBefore(businessHoursStart) || time.isAfter(businessHoursEnd)) {
                    anomalies.add(new Anomaly(
                            scanId,
                            entry.getRawLine(),
                            "Off-Hours Activity: Access by '" + user + "' at " + time + " outside working hours (" + businessHoursStart + "-" + businessHoursEnd + ")",
                            Anomaly.Severity.MEDIUM
                    ));
                }
            }

            // Rule 1: Brute-Force Burst (>= threshold failed logins within sliding window)
            if (event.contains("FAIL")) {
                Deque<LogEntry> queue = failedLoginsByIp.computeIfAbsent(ip, k -> new ArrayDeque<>());
                queue.addLast(entry);

                if (entryTime != null) {
                    // Evict entries older than timeWindowMinutes from window
                    while (!queue.isEmpty()) {
                        LocalDateTime firstTime = queue.peekFirst().getParsedDateTime();
                        if (firstTime != null && Duration.between(firstTime, entryTime).toMinutes() > timeWindowMinutes) {
                            queue.pollFirst();
                        } else {
                            break;
                        }
                    }
                }

                if (queue.size() >= failedLoginThreshold && !alreadyFlaggedBurstIps.contains(ip + "@" + entry.getTimestamp())) {
                    alreadyFlaggedBurstIps.add(ip + "@" + entry.getTimestamp());
                    anomalies.add(new Anomaly(
                            scanId,
                            entry.getRawLine(),
                            "Brute Force Detected: " + queue.size() + " failed logins from " + ip + " within " + timeWindowMinutes + " minutes",
                            Anomaly.Severity.HIGH
                    ));
                }
            }
        }

        // Persist anomalies if DAO provided
        if (anomalyDAO != null && !anomalies.isEmpty()) {
            anomalyDAO.insertBatch(anomalies);
        }

        LOGGER.info("Log evaluation complete. Flagged " + anomalies.size() + " anomalies.");
        return anomalies;
    }
}
