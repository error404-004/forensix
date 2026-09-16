package com.forensix.ui;

import com.forensix.model.Scan;
import com.forensix.service.ServiceContext;
import com.forensix.service.VerificationResult;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Main dashboard view summarizing baseline health, recent scan results, and audit integrity.
 */
public class DashboardPanel extends JPanel {

    private final ServiceContext context;
    private final MainWindow mainWindow;

    private JLabel baselineCountLabel;
    private JLabel lastScanLabel;
    private JLabel changesCountLabel;
    private JLabel anomaliesCountLabel;
    private JLabel auditStatusBadge;

    private JTable recentActivityTable;
    private DefaultTableModel tableModel;

    private JButton btnRunScan;
    private JButton btnCreateBaseline;
    private JButton btnVerifyAudit;

    public DashboardPanel(ServiceContext context, MainWindow mainWindow) {
        this.context = context;
        this.mainWindow = mainWindow;
        setLayout(new BorderLayout(15, 15));
        setBackground(UIHelper.BG_COLOR);
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        initComponents();
        refreshMetrics();
    }

    private void initComponents() {
        // --- Top: Header & Quick Action Buttons ---
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));
        topPanel.setOpaque(false);

        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        titlePanel.setOpaque(false);

        JLabel lblTitle = new JLabel("System Security & Integrity Dashboard");
        lblTitle.setFont(UIHelper.FONT_TITLE);
        lblTitle.setForeground(UIHelper.PRIMARY_COLOR);

        JLabel lblSub = new JLabel("Cryptographic File Integrity Monitoring & DFIR Audit Chain");
        lblSub.setFont(UIHelper.FONT_SMALL);
        lblSub.setForeground(UIHelper.TEXT_MUTED);

        titlePanel.add(lblTitle);
        titlePanel.add(Box.createVerticalStrut(3));
        titlePanel.add(lblSub);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionPanel.setOpaque(false);

        btnCreateBaseline = UIHelper.createStyledButton("Create Baseline", UIHelper.SECONDARY_COLOR);
        btnRunScan = UIHelper.createStyledButton("Run Scan Now", UIHelper.SUCCESS_COLOR);
        btnVerifyAudit = UIHelper.createStyledButton("Verify Audit Chain", UIHelper.PRIMARY_COLOR);

        btnCreateBaseline.addActionListener(e -> triggerCreateBaseline());
        btnRunScan.addActionListener(e -> triggerScan());
        btnVerifyAudit.addActionListener(e -> triggerVerifyAudit());

        actionPanel.add(btnCreateBaseline);
        actionPanel.add(btnRunScan);
        actionPanel.add(btnVerifyAudit);

        topPanel.add(titlePanel, BorderLayout.WEST);
        topPanel.add(actionPanel, BorderLayout.EAST);
        add(topPanel, BorderLayout.NORTH);

        // --- Center: Metric Cards & Recent Findings Table ---
        JPanel centerPanel = new JPanel(new BorderLayout(15, 15));
        centerPanel.setOpaque(false);

        // Metric Cards Grid
        JPanel metricsGrid = new JPanel(new GridLayout(1, 5, 12, 12));
        metricsGrid.setOpaque(false);

        JPanel card1 = UIHelper.createCardPanel();
        card1.setLayout(new BorderLayout(5, 5));
        JLabel c1Title = new JLabel("BASELINED FILES");
        c1Title.setFont(UIHelper.FONT_SMALL);
        c1Title.setForeground(UIHelper.TEXT_MUTED);
        baselineCountLabel = new JLabel("0");
        baselineCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        baselineCountLabel.setForeground(UIHelper.PRIMARY_COLOR);
        card1.add(c1Title, BorderLayout.NORTH);
        card1.add(baselineCountLabel, BorderLayout.CENTER);

        JPanel card2 = UIHelper.createCardPanel();
        card2.setLayout(new BorderLayout(5, 5));
        JLabel c2Title = new JLabel("LAST SCAN");
        c2Title.setFont(UIHelper.FONT_SMALL);
        c2Title.setForeground(UIHelper.TEXT_MUTED);
        lastScanLabel = new JLabel("Never");
        lastScanLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        lastScanLabel.setForeground(UIHelper.SECONDARY_COLOR);
        card2.add(c2Title, BorderLayout.NORTH);
        card2.add(lastScanLabel, BorderLayout.CENTER);

        JPanel card3 = UIHelper.createCardPanel();
        card3.setLayout(new BorderLayout(5, 5));
        JLabel c3Title = new JLabel("FILE CHANGES");
        c3Title.setFont(UIHelper.FONT_SMALL);
        c3Title.setForeground(UIHelper.TEXT_MUTED);
        changesCountLabel = new JLabel("0");
        changesCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        changesCountLabel.setForeground(UIHelper.WARNING_COLOR);
        card3.add(c3Title, BorderLayout.NORTH);
        card3.add(changesCountLabel, BorderLayout.CENTER);

        JPanel card4 = UIHelper.createCardPanel();
        card4.setLayout(new BorderLayout(5, 5));
        JLabel c4Title = new JLabel("LOG ANOMALIES");
        c4Title.setFont(UIHelper.FONT_SMALL);
        c4Title.setForeground(UIHelper.TEXT_MUTED);
        anomaliesCountLabel = new JLabel("0");
        anomaliesCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        anomaliesCountLabel.setForeground(UIHelper.DANGER_COLOR);
        card4.add(c4Title, BorderLayout.NORTH);
        card4.add(anomaliesCountLabel, BorderLayout.CENTER);

        JPanel card5 = UIHelper.createCardPanel();
        card5.setLayout(new BorderLayout(5, 5));
        JLabel c5Title = new JLabel("AUDIT LOG INTEGRITY");
        c5Title.setFont(UIHelper.FONT_SMALL);
        c5Title.setForeground(UIHelper.TEXT_MUTED);
        auditStatusBadge = new JLabel("UNCHECKED");
        auditStatusBadge.setFont(new Font("Segoe UI", Font.BOLD, 13));
        auditStatusBadge.setForeground(UIHelper.TEXT_MUTED);
        card5.add(c5Title, BorderLayout.NORTH);
        card5.add(auditStatusBadge, BorderLayout.CENTER);

        metricsGrid.add(card1);
        metricsGrid.add(card2);
        metricsGrid.add(card3);
        metricsGrid.add(card4);
        metricsGrid.add(card5);

        centerPanel.add(metricsGrid, BorderLayout.NORTH);

        // Activity Table
        JPanel tableContainer = UIHelper.createCardPanel();
        tableContainer.setLayout(new BorderLayout(10, 10));

        JLabel tblHeader = new JLabel("Latest Security Findings & Integrity Activity");
        tblHeader.setFont(UIHelper.FONT_HEADER);
        tblHeader.setForeground(UIHelper.PRIMARY_COLOR);
        tableContainer.add(tblHeader, BorderLayout.NORTH);

        String[] cols = {"Category", "Type / Severity", "Detail / Path", "Timestamp"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        recentActivityTable = new JTable(tableModel);
        recentActivityTable.setFont(UIHelper.FONT_BODY);
        recentActivityTable.setRowHeight(24);
        recentActivityTable.getTableHeader().setFont(UIHelper.FONT_BOLD);
        recentActivityTable.getTableHeader().setBackground(UIHelper.BG_COLOR);

        JScrollPane scroll = new JScrollPane(recentActivityTable);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(230, 230, 230)));
        tableContainer.add(scroll, BorderLayout.CENTER);

        centerPanel.add(tableContainer, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);
    }

    public void refreshMetrics() {
        int baselineCount = context.getBaselineDAO().count();
        baselineCountLabel.setText(String.valueOf(baselineCount));

        Scan lastScan = context.getScanDAO().getLastScan();
        if (lastScan != null) {
            lastScanLabel.setText("#" + lastScan.getId() + " (" + lastScan.getStatus() + ")");
            int changes = context.getEventDAO().findByScanId(lastScan.getId()).stream()
                    .filter(e -> e.getEventType() != com.forensix.model.FileEvent.EventType.UNCHANGED)
                    .toList().size();
            changesCountLabel.setText(String.valueOf(changes));

            int anomalies = context.getAnomalyDAO().findByScanId(lastScan.getId()).size();
            anomaliesCountLabel.setText(String.valueOf(anomalies));
        } else {
            lastScanLabel.setText("No scans yet");
            changesCountLabel.setText("0");
            anomaliesCountLabel.setText("0");
        }

        // Check audit chain
        VerificationResult v = context.getAuditService().verifyChain();
        if (v.isValid()) {
            auditStatusBadge.setText("SEALED & VALID");
            auditStatusBadge.setForeground(UIHelper.SUCCESS_COLOR);
        } else {
            auditStatusBadge.setText("TAMPERING DETECTED!");
            auditStatusBadge.setForeground(UIHelper.DANGER_COLOR);
        }

        // Populate recent activity table
        tableModel.setRowCount(0);
        if (lastScan != null) {
            for (var ev : context.getEventDAO().findByScanId(lastScan.getId())) {
                if (ev.getEventType() != com.forensix.model.FileEvent.EventType.UNCHANGED) {
                    tableModel.addRow(new Object[]{"FILE_EVENT", ev.getEventType().name(), ev.getPath(), ev.getDetectedAt()});
                }
            }
            for (var an : context.getAnomalyDAO().findByScanId(lastScan.getId())) {
                tableModel.addRow(new Object[]{"ANOMALY", an.getSeverity().name(), an.getRuleTriggered(), an.getDetectedAt()});
            }
        }
    }

    private void triggerCreateBaseline() {
        String dir = context.getConfig().getMonitoredDirectory();
        int confirm = JOptionPane.showConfirmDialog(this,
                "Establish baseline for: " + dir + "?\nThis will record current SHA-256 hashes of all files in this path.",
                "Create Baseline", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        btnCreateBaseline.setEnabled(false);
        mainWindow.setStatus("Establishing baseline hashes for " + dir + "...");

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                var records = context.createBaseline(Paths.get(dir));
                return records.size();
            }

            @Override
            protected void done() {
                btnCreateBaseline.setEnabled(true);
                try {
                    int count = get();
                    mainWindow.setStatus("Baseline created successfully: " + count + " files recorded.");
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                            "Cryptographic baseline established for " + count + " files.",
                            "Baseline Created", JOptionPane.INFORMATION_MESSAGE);
                    refreshMetrics();
                    mainWindow.notifyAllPanelsRefresh();
                } catch (Exception e) {
                    mainWindow.setStatus("Baseline creation failed.");
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                            "Failed to establish baseline: " + e.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void triggerScan() {
        String dir = context.getConfig().getMonitoredDirectory();
        String logPath = context.getConfig().getLogFilePath();

        btnRunScan.setEnabled(false);
        mainWindow.setStatus("Executing full security audit scan...");

        SwingWorker<Scan, Void> worker = new SwingWorker<>() {
            @Override
            protected Scan doInBackground() {
                Path d = Paths.get(dir);
                Path l = (logPath != null && !logPath.isBlank()) ? Paths.get(logPath) : null;
                return context.executeFullScan(d, l);
            }

            @Override
            protected void done() {
                btnRunScan.setEnabled(true);
                try {
                    Scan scan = get();
                    mainWindow.setStatus("Scan #" + scan.getId() + " finished successfully.");
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                            "Security Scan #" + scan.getId() + " completed.\n" +
                            "Files checked: " + scan.getEvents().size() + "\n" +
                            "Changes detected: " + (scan.getAddedCount() + scan.getModifiedCount() + scan.getDeletedCount()) + "\n" +
                            "Log anomalies flagged: " + scan.getAnomalies().size() + "\n" +
                            "Audit record cryptographically chained.",
                            "Scan Complete", JOptionPane.INFORMATION_MESSAGE);
                    refreshMetrics();
                    mainWindow.notifyAllPanelsRefresh();
                } catch (Exception e) {
                    mainWindow.setStatus("Scan failed.");
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                            "Scan execution error: " + e.getMessage(),
                            "Scan Failure", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void triggerVerifyAudit() {
        VerificationResult result = context.getAuditService().verifyChain();
        refreshMetrics();
        if (result.isValid()) {
            JOptionPane.showMessageDialog(this,
                    "Cryptographic Audit Chain Verified Successfully!\n" +
                    "All " + result.getTotalRecordsVerified() + " records validated.\n" +
                    "Chain-of-custody is intact with zero tampering detected.",
                    "Audit Chain Verified", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "CRITICAL SECURITY ALERT: Tampering Detected!\n\n" +
                    "Broken Record ID : #" + result.getBrokenRecordId() + "\n" +
                    "Violation Type   : " + result.getBrokenField() + "\n" +
                    "Expected Hash    : " + result.getExpectedHash() + "\n" +
                    "Found Hash       : " + result.getActualHash() + "\n\n" +
                    "The SQLite database has been altered outside authorized application workflows!",
                    "Tamper Evidence Alert", JOptionPane.ERROR_MESSAGE);
        }
    }
}
