package com.forensix.model;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Encapsulates application configuration settings.
 */
public class Config {
    private String monitoredDirectory = "./test-dir";
    private String logFilePath = "src/main/resources/sample-logs/sample-auth.log";
    private int failedLoginThreshold = 5;
    private int timeWindowMinutes = 5;
    private String businessHoursStart = "08:00";
    private String businessHoursEnd = "19:00";
    private String blacklistedIps = "198.51.100.23,203.0.113.88,192.0.2.1";
    private String suspiciousUsers = "root,admin,guest,oracle,postgres,test";
    private int scanIntervalSeconds = 60;
    private String databasePath = "data/forensix.db";
    private String reportsDirectory = "reports";

    public Config() {}

    public String getMonitoredDirectory() { return monitoredDirectory; }
    public void setMonitoredDirectory(String monitoredDirectory) { this.monitoredDirectory = monitoredDirectory; }

    public String getLogFilePath() { return logFilePath; }
    public void setLogFilePath(String logFilePath) { this.logFilePath = logFilePath; }

    public int getFailedLoginThreshold() { return failedLoginThreshold; }
    public void setFailedLoginThreshold(int failedLoginThreshold) { this.failedLoginThreshold = failedLoginThreshold; }

    public int getTimeWindowMinutes() { return timeWindowMinutes; }
    public void setTimeWindowMinutes(int timeWindowMinutes) { this.timeWindowMinutes = timeWindowMinutes; }

    public String getBusinessHoursStart() { return businessHoursStart; }
    public void setBusinessHoursStart(String businessHoursStart) { this.businessHoursStart = businessHoursStart; }

    public String getBusinessHoursEnd() { return businessHoursEnd; }
    public void setBusinessHoursEnd(String businessHoursEnd) { this.businessHoursEnd = businessHoursEnd; }

    public String getBlacklistedIps() { return blacklistedIps; }
    public void setBlacklistedIps(String blacklistedIps) { this.blacklistedIps = blacklistedIps; }

    public String getSuspiciousUsers() { return suspiciousUsers; }
    public void setSuspiciousUsers(String suspiciousUsers) { this.suspiciousUsers = suspiciousUsers; }

    public int getScanIntervalSeconds() { return scanIntervalSeconds; }
    public void setScanIntervalSeconds(int scanIntervalSeconds) { this.scanIntervalSeconds = scanIntervalSeconds; }

    public String getDatabasePath() { return databasePath; }
    public void setDatabasePath(String databasePath) { this.databasePath = databasePath; }

    public String getReportsDirectory() { return reportsDirectory; }
    public void setReportsDirectory(String reportsDirectory) { this.reportsDirectory = reportsDirectory; }

    public LocalTime getParsedBusinessStart() {
        try {
            return LocalTime.parse(businessHoursStart, DateTimeFormatter.ofPattern("HH:mm"));
        } catch (Exception e) {
            return LocalTime.of(8, 0);
        }
    }

    public LocalTime getParsedBusinessEnd() {
        try {
            return LocalTime.parse(businessHoursEnd, DateTimeFormatter.ofPattern("HH:mm"));
        } catch (Exception e) {
            return LocalTime.of(19, 0);
        }
    }

    public Set<String> getBlacklistedIpsSet() {
        Set<String> set = new HashSet<>();
        if (blacklistedIps != null) {
            for (String ip : blacklistedIps.split(",")) {
                if (!ip.trim().isEmpty()) set.add(ip.trim());
            }
        }
        return set;
    }

    public Set<String> getSuspiciousUsersSet() {
        Set<String> set = new HashSet<>();
        if (suspiciousUsers != null) {
            for (String u : suspiciousUsers.split(",")) {
                if (!u.trim().isEmpty()) set.add(u.trim().toLowerCase());
            }
        }
        return set;
    }
}
