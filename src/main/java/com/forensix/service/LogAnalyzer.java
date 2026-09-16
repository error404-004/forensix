package com.forensix.service;

import com.forensix.model.Anomaly;
import com.forensix.model.LogEntry;

import java.nio.file.Path;
import java.util.List;

/**
 * Service contract for log file ingestion and rule-based anomaly detection.
 */
public interface LogAnalyzer {

    /**
     * Ingests and parses a log file line-by-line into structured LogEntry objects.
     * Fault-tolerant against malformed lines.
     *
     * @param logFilePath path to log file
     * @return parsed log entries
     */
    List<LogEntry> parse(Path logFilePath);

    /**
     * Evaluates security rules against a sequence of log entries.
     *
     * @param entries log entries to analyze
     * @param scanId associated scan session ID
     * @return detected security anomalies
     */
    List<Anomaly> evaluate(List<LogEntry> entries, long scanId);

    /**
     * Returns the count of malformed lines skipped during the last parse operation.
     */
    int getParseErrorsCount();
}
