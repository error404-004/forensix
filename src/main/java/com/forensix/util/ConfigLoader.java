package com.forensix.util;

import com.forensix.model.Config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Loads, validates, and persists application configuration settings.
 */
public class ConfigLoader {
    private static final Logger LOGGER = Logger.getLogger(ConfigLoader.class.getName());
    public static final String DEFAULT_CONFIG_FILE = "config.properties";

    private final String configFilePath;

    public ConfigLoader() {
        this(DEFAULT_CONFIG_FILE);
    }

    public ConfigLoader(String configFilePath) {
        this.configFilePath = configFilePath;
    }

    /**
     * Loads the Config object from external file or classpath resource with fallbacks.
     */
    public Config loadConfig() {
        Config config = new Config();
        Properties props = new Properties();

        // 1. Try local file path first
        File file = new File(configFilePath);
        if (file.exists() && file.canRead()) {
            try (InputStream in = new FileInputStream(file)) {
                props.load(in);
                LOGGER.info("Loaded configuration from file: " + file.getAbsolutePath());
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Error reading config file: " + configFilePath, e);
            }
        } else {
            // 2. Try classpath resource
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(configFilePath)) {
                if (in != null) {
                    props.load(in);
                    LOGGER.info("Loaded configuration from classpath resource: " + configFilePath);
                } else {
                    LOGGER.info("Config resource not found, using default configuration.");
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Error loading classpath config resource", e);
            }
        }

        // Apply values if present
        if (props.containsKey("monitored.directory")) {
            config.setMonitoredDirectory(props.getProperty("monitored.directory").trim());
        }
        if (props.containsKey("log.file.path")) {
            config.setLogFilePath(props.getProperty("log.file.path").trim());
        }
        if (props.containsKey("failed.login.threshold")) {
            try {
                config.setFailedLoginThreshold(Integer.parseInt(props.getProperty("failed.login.threshold").trim()));
            } catch (NumberFormatException ignored) {}
        }
        if (props.containsKey("time.window.minutes")) {
            try {
                config.setTimeWindowMinutes(Integer.parseInt(props.getProperty("time.window.minutes").trim()));
            } catch (NumberFormatException ignored) {}
        }
        if (props.containsKey("business.hours.start")) {
            config.setBusinessHoursStart(props.getProperty("business.hours.start").trim());
        }
        if (props.containsKey("business.hours.end")) {
            config.setBusinessHoursEnd(props.getProperty("business.hours.end").trim());
        }
        if (props.containsKey("blacklisted.ips")) {
            config.setBlacklistedIps(props.getProperty("blacklisted.ips").trim());
        }
        if (props.containsKey("suspicious.users")) {
            config.setSuspiciousUsers(props.getProperty("suspicious.users").trim());
        }
        if (props.containsKey("scan.interval.seconds")) {
            try {
                config.setScanIntervalSeconds(Integer.parseInt(props.getProperty("scan.interval.seconds").trim()));
            } catch (NumberFormatException ignored) {}
        }
        if (props.containsKey("database.path")) {
            config.setDatabasePath(props.getProperty("database.path").trim());
        }
        if (props.containsKey("reports.directory")) {
            config.setReportsDirectory(props.getProperty("reports.directory").trim());
        }

        return config;
    }

    /**
     * Persists updated configuration settings to file.
     */
    public void saveConfig(Config config) throws IOException {
        Properties props = new Properties();
        props.setProperty("monitored.directory", config.getMonitoredDirectory());
        props.setProperty("log.file.path", config.getLogFilePath());
        props.setProperty("failed.login.threshold", String.valueOf(config.getFailedLoginThreshold()));
        props.setProperty("time.window.minutes", String.valueOf(config.getTimeWindowMinutes()));
        props.setProperty("business.hours.start", config.getBusinessHoursStart());
        props.setProperty("business.hours.end", config.getBusinessHoursEnd());
        props.setProperty("blacklisted.ips", config.getBlacklistedIps());
        props.setProperty("suspicious.users", config.getSuspiciousUsers());
        props.setProperty("scan.interval.seconds", String.valueOf(config.getScanIntervalSeconds()));
        props.setProperty("database.path", config.getDatabasePath());
        props.setProperty("reports.directory", config.getReportsDirectory());

        File file = new File(configFilePath);
        try (OutputStream out = new FileOutputStream(file)) {
            props.store(out, "FORENSIX Configuration Updated");
            LOGGER.info("Configuration saved successfully to: " + file.getAbsolutePath());
        }
    }
}
