package com.forensix;

import com.forensix.service.ServiceContext;
import com.forensix.service.VerificationResult;
import com.forensix.ui.MainWindow;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Main application entry point for FORENSIX.
 * Configures application logging, supports CLI workflows, and boots the Swing GUI.
 */
public class Main {
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        initLogging();

        System.out.println("================================================================================");
        System.out.println("  FORENSIX — File Integrity Monitoring & Security Audit Toolkit v1.0.0");
        System.out.println("================================================================================");
        LOGGER.info("FORENSIX initializing...");

        boolean cliMode = false;
        String action = null;
        String targetDir = null;

        for (int i = 0; i < args.length; i++) {
            if ("--headless".equalsIgnoreCase(args[i]) || "--cli".equalsIgnoreCase(args[i])) {
                cliMode = true;
            } else if ("--baseline".equalsIgnoreCase(args[i])) {
                cliMode = true;
                action = "baseline";
                if (i + 1 < args.length) targetDir = args[++i];
            } else if ("--scan".equalsIgnoreCase(args[i])) {
                cliMode = true;
                action = "scan";
                if (i + 1 < args.length) targetDir = args[++i];
            } else if ("--verify-audit".equalsIgnoreCase(args[i])) {
                cliMode = true;
                action = "verify-audit";
            }
        }

        if (cliMode) {
            runCli(action, targetDir);
        } else {
            LOGGER.info("Starting Swing Desktop User Interface...");
            MainWindow.launch();
        }
    }

    private static void initLogging() {
        try {
            // Rotating log file, max 2MB, 3 files
            FileHandler fileHandler = new FileHandler("forensix.log", 2097152, 3, true);
            fileHandler.setFormatter(new SimpleFormatter());
            fileHandler.setLevel(Level.INFO);
            Logger rootLogger = Logger.getLogger("");
            rootLogger.addHandler(fileHandler);
            LOGGER.info("Logging initialized to forensix.log");
        } catch (IOException e) {
            System.err.println("Could not configure log file handler: " + e.getMessage());
        }
    }

    private static void runCli(String action, String targetDir) {
        ServiceContext context = new ServiceContext();
        Path dir = Paths.get(targetDir != null ? targetDir : context.getConfig().getMonitoredDirectory());

        if ("baseline".equalsIgnoreCase(action)) {
            System.out.println("[CLI] Creating baseline for: " + dir);
            var records = context.createBaseline(dir);
            System.out.println("[CLI] Baseline created with " + records.size() + " files.");
        } else if ("scan".equalsIgnoreCase(action)) {
            System.out.println("[CLI] Running full security audit scan on: " + dir);
            Path logPath = Paths.get(context.getConfig().getLogFilePath());
            var scan = context.executeFullScan(dir, logPath);
            System.out.println("[CLI] Scan #" + scan.getId() + " completed. Status: " + scan.getStatus());
            System.out.println("[CLI] Events: " + scan.getEvents().size() + " | Anomalies: " + scan.getAnomalies().size());
        } else if ("verify-audit".equalsIgnoreCase(action)) {
            System.out.println("[CLI] Verifying cryptographic audit chain...");
            VerificationResult res = context.getAuditService().verifyChain();
            System.out.println("[CLI] Result: " + res);
        } else {
            System.out.println("[CLI] FORENSIX CLI ready. Service context initialized.");
        }
    }
}
