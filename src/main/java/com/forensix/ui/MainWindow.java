package com.forensix.ui;

import com.forensix.service.ServiceContext;
import com.forensix.service.VerificationResult;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main application window for FORENSIX desktop user interface.
 */
public class MainWindow extends JFrame {
    private static final Logger LOGGER = Logger.getLogger(MainWindow.class.getName());

    private final ServiceContext context;

    private JTabbedPane tabbedPane;
    private DashboardPanel dashboardPanel;
    private FimPanel fimPanel;
    private LogAnalysisPanel logAnalysisPanel;
    private AuditPanel auditPanel;
    private ConfigPanel configPanel;
    private ReportViewerPanel reportViewerPanel;

    private JLabel statusLabel;
    private JLabel auditChainStatusLabel;

    public MainWindow(ServiceContext context) {
        super("FORENSIX — File Integrity & Security Audit Toolkit");
        this.context = context;

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1050, 720));
        setPreferredSize(new Dimension(1150, 780));
        setLocationRelativeTo(null);

        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());
        getContentPane().setBackground(UIHelper.BG_COLOR);

        // --- Top Application Header ---
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(UIHelper.PRIMARY_COLOR);
        header.setBorder(BorderFactory.createEmptyBorder(14, 20, 14, 20));

        JPanel titleBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        titleBox.setOpaque(false);

        JLabel logoLabel = new JLabel("🛡️ FORENSIX");
        logoLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        logoLabel.setForeground(Color.WHITE);

        JLabel subLabel = new JLabel("|  Cryptographic FIM & Tamper-Evident Security Audit Toolkit");
        subLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        subLabel.setForeground(new Color(189, 195, 199));

        titleBox.add(logoLabel);
        titleBox.add(subLabel);
        header.add(titleBox, BorderLayout.WEST);

        JLabel versionLabel = new JLabel("v1.0.0 (Java 17 / SQLite)");
        versionLabel.setFont(UIHelper.FONT_SMALL);
        versionLabel.setForeground(new Color(149, 165, 166));
        header.add(versionLabel, BorderLayout.EAST);

        add(header, BorderLayout.NORTH);

        // --- Center Tabbed View ---
        tabbedPane = new JTabbedPane();
        tabbedPane.setFont(UIHelper.FONT_BOLD);
        tabbedPane.setBackground(UIHelper.BG_COLOR);

        dashboardPanel = new DashboardPanel(context, this);
        fimPanel = new FimPanel(context, this);
        logAnalysisPanel = new LogAnalysisPanel(context, this);
        auditPanel = new AuditPanel(context, this);
        configPanel = new ConfigPanel(context, this);
        reportViewerPanel = new ReportViewerPanel(context, this);

        tabbedPane.addTab("Dashboard", dashboardPanel);
        tabbedPane.addTab("File Integrity (FIM)", fimPanel);
        tabbedPane.addTab("Log Analysis", logAnalysisPanel);
        tabbedPane.addTab("Audit Trail & Verification", auditPanel);
        tabbedPane.addTab("Reports", reportViewerPanel);
        tabbedPane.addTab("Configuration", configPanel);

        tabbedPane.addChangeListener(e -> onTabChanged());
        add(tabbedPane, BorderLayout.CENTER);

        // --- Bottom Status Bar ---
        JPanel statusBar = new JPanel(new BorderLayout(10, 0));
        statusBar.setBackground(Color.WHITE);
        statusBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(222, 226, 230)),
                BorderFactory.createEmptyBorder(6, 15, 6, 15)
        ));

        statusLabel = new JLabel("Ready. SQLite database connected at: " + context.getConfig().getDatabasePath());
        statusLabel.setFont(UIHelper.FONT_SMALL);
        statusLabel.setForeground(UIHelper.TEXT_MUTED);

        auditChainStatusLabel = new JLabel("● Audit Chain: VALID");
        auditChainStatusLabel.setFont(UIHelper.FONT_SMALL);
        auditChainStatusLabel.setForeground(UIHelper.SUCCESS_COLOR);

        statusBar.add(statusLabel, BorderLayout.WEST);
        statusBar.add(auditChainStatusLabel, BorderLayout.EAST);
        add(statusBar, BorderLayout.SOUTH);
    }

    private void onTabChanged() {
        int idx = tabbedPane.getSelectedIndex();
        if (idx == 0) dashboardPanel.refreshMetrics();
        else if (idx == 1) fimPanel.refreshPanel();
        else if (idx == 2) logAnalysisPanel.refreshPanel();
        else if (idx == 3) auditPanel.refreshPanel();
        else if (idx == 4) reportViewerPanel.refreshPanel();
        updateAuditChainStatus();
    }

    public void notifyAllPanelsRefresh() {
        dashboardPanel.refreshMetrics();
        fimPanel.refreshPanel();
        logAnalysisPanel.refreshPanel();
        auditPanel.refreshPanel();
        reportViewerPanel.refreshPanel();
        updateAuditChainStatus();
    }

    public void updateAuditChainStatus() {
        VerificationResult result = context.getAuditService().verifyChain();
        if (result.isValid()) {
            auditChainStatusLabel.setText("● Audit Chain: VERIFIED INTACT (" + result.getTotalRecordsVerified() + " records)");
            auditChainStatusLabel.setForeground(UIHelper.SUCCESS_COLOR);
        } else {
            auditChainStatusLabel.setText("● TAMPERING DETECTED at record #" + result.getBrokenRecordId());
            auditChainStatusLabel.setForeground(UIHelper.DANGER_COLOR);
        }
    }

    public void setStatus(String message) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    /**
     * Boots the UI on the Event Dispatch Thread (EDT).
     */
    public static void launch() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> {
            try {
                ServiceContext context = new ServiceContext();
                MainWindow window = new MainWindow(context);
                window.setVisible(true);
                LOGGER.info("FORENSIX graphical interface launched successfully.");
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to launch main window", e);
                e.printStackTrace();
            }
        });
    }
}
