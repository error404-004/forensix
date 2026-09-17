package com.forensix;

import com.forensix.dao.AuditLogDAO;
import com.forensix.dao.DatabaseManager;
import com.forensix.model.Scan;
import com.forensix.service.AuditServiceImpl;
import com.forensix.service.ServiceContext;
import com.forensix.service.VerificationResult;
import com.forensix.ui.MainWindow;
import com.forensix.ui.UIHelper;

import javax.imageio.ImageIO;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Generates high-quality JPG screenshots of all FORENSIX views with live data.
 */
public class ScreenshotGenerator {

    public static void main(String[] args) throws Exception {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        Path screenshotDir = Paths.get("docs/screenshots");
        Files.createDirectories(screenshotDir);

        // Ensure real test data exists
        Path testDir = Paths.get("test-dir");
        Files.createDirectories(testDir);
        Files.writeString(testDir.resolve("config.conf"), "SERVER_PORT=8080\nDEBUG=FALSE\nTIMEOUT=30");
        Files.writeString(testDir.resolve("app.bin"), "BINARY_DATA_V1_PRODUCTION_BUILD");
        Files.writeString(testDir.resolve("secret.key"), "AES256_GCM_ENCRYPTION_KEY_SECRET");

        ServiceContext context = new ServiceContext();
        context.createBaseline(testDir);

        // Real alterations
        Files.writeString(testDir.resolve("config.conf"), "SERVER_PORT=9999 # TAMPERED BY ATTACKER\nDEBUG=TRUE");
        Files.writeString(testDir.resolve("added_module.txt"), "UNAUTHORIZED_BACKDOOR_SCRIPT_ADDED");
        Files.deleteIfExists(testDir.resolve("secret.key"));

        Path sampleLog = Paths.get("src/main/resources/sample-logs/sample-auth.log");
        Scan scan = context.executeFullScan(testDir, sampleLog);
        System.out.println("Executed real Scan #" + scan.getId() + " (Events: " + scan.getEvents().size() + ", Anomalies: " + scan.getAnomalies().size() + ")");

        // Launch MainWindow
        final MainWindow[] windowHolder = new MainWindow[1];
        SwingUtilities.invokeAndWait(() -> {
            MainWindow window = new MainWindow(context);
            window.setSize(1180, 780);
            window.setVisible(true);
            windowHolder[0] = window;
        });

        MainWindow window = windowHolder[0];
        Thread.sleep(600); // wait for initial render

        JTabbedPane tabbedPane = findTabbedPane(window);

        // 1. Dashboard Overview
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(0);
            window.notifyAllPanelsRefresh();
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("01_dashboard_overview.jpg"));

        // 2. File Integrity Monitoring (FIM)
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(1);
            window.notifyAllPanelsRefresh();
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("02_fim_scan_results.jpg"));

        // 3. Log Analysis
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(2);
            window.notifyAllPanelsRefresh();
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("03_log_analysis_findings.jpg"));

        // 4. Audit Trail (Intact & Verified)
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(3);
            var auditPanel = (com.forensix.ui.AuditPanel) tabbedPane.getComponentAt(3);
            auditPanel.runVerification();
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("04_audit_chain_verified.jpg"));

        // 5. Forensic Reports
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(4);
            window.notifyAllPanelsRefresh();
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("05_forensic_report_viewer.jpg"));

        // 6. Configuration & Scheduler
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(5);
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("06_configuration_settings.jpg"));

        // Dispose primary window
        SwingUtilities.invokeAndWait(window::dispose);

        // 7. Capture Tamper Detected State
        generateTamperScreenshot(screenshotDir);

        System.out.println("All screenshots successfully captured in: " + screenshotDir.toAbsolutePath());
        System.exit(0);
    }

    private static void generateTamperScreenshot(Path screenshotDir) throws Exception {
        Path origDb = Paths.get("data/forensix.db");
        Path tamperDb = Paths.get("data/disposable_tamper_screen.db");
        Files.copy(origDb, tamperDb, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        DatabaseManager dm = new DatabaseManager(tamperDb.toString());
        try (var conn = dm.getConnection(); var stmt = conn.createStatement()) {
            stmt.executeUpdate("UPDATE audit_log SET payload = 'TAMPERED_COVER_TRACKS' WHERE id = 4;");
        }

        final MainWindow[] windowHolder = new MainWindow[1];
        SwingUtilities.invokeAndWait(() -> {
            ServiceContext tamperContext = new ServiceContext(tamperDb.toString());
            MainWindow window = new MainWindow(tamperContext);
            window.setSize(1180, 780);
            window.setVisible(true);
            windowHolder[0] = window;
        });

        MainWindow window = windowHolder[0];
        Thread.sleep(600);

        JTabbedPane tabbedPane = findTabbedPane(window);
        SwingUtilities.invokeAndWait(() -> {
            tabbedPane.setSelectedIndex(3); // Audit tab
            var auditPanel = (com.forensix.ui.AuditPanel) tabbedPane.getComponentAt(3);
            auditPanel.runVerification();
        });
        Thread.sleep(300);
        captureWindow(window, screenshotDir.resolve("07_audit_tamper_detected.jpg"));

        SwingUtilities.invokeAndWait(window::dispose);
        Files.deleteIfExists(tamperDb);
    }

    private static void captureWindow(MainWindow window, Path outputPath) {
        int w = window.getWidth();
        int h = window.getHeight();
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = img.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2.setColor(Color.WHITE);
        g2.fillRect(0, 0, w, h);

        window.printAll(g2);
        g2.dispose();

        try {
            ImageIO.write(img, "jpg", outputPath.toFile());
            System.out.println("Saved: " + outputPath.getFileName() + " (" + Files.size(outputPath) + " bytes)");
        } catch (Exception e) {
            System.err.println("Error saving " + outputPath + ": " + e.getMessage());
        }
    }

    private static JTabbedPane findTabbedPane(Component comp) {
        if (comp instanceof JTabbedPane) {
            return (JTabbedPane) comp;
        }
        if (comp instanceof java.awt.Container) {
            for (Component child : ((java.awt.Container) comp).getComponents()) {
                JTabbedPane found = findTabbedPane(child);
                if (found != null) return found;
            }
        }
        return null;
    }
}
