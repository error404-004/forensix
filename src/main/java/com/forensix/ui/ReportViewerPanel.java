package com.forensix.ui;

import com.forensix.model.Scan;
import com.forensix.service.ServiceContext;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Report viewer panel for inspecting and exporting formatted forensic audit reports.
 */
public class ReportViewerPanel extends JPanel {

    private final ServiceContext context;
    private final MainWindow mainWindow;

    private JComboBox<String> scanSelector;
    private JTextArea reportTextArea;
    private JButton btnExport;

    public ReportViewerPanel(ServiceContext context, MainWindow mainWindow) {
        this.context = context;
        this.mainWindow = mainWindow;
        setLayout(new BorderLayout(15, 15));
        setBackground(UIHelper.BG_COLOR);
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        initComponents();
        refreshPanel();
    }

    private void initComponents() {
        // --- Top Bar ---
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));
        topPanel.setOpaque(false);

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        leftPanel.setOpaque(false);
        leftPanel.add(new JLabel("Select Scan:"));

        scanSelector = new JComboBox<>();
        scanSelector.setFont(UIHelper.FONT_BODY);
        scanSelector.addActionListener(e -> loadSelectedReport());
        leftPanel.add(scanSelector);

        btnExport = UIHelper.createStyledButton("Export Report to Disk", UIHelper.SUCCESS_COLOR);
        btnExport.addActionListener(e -> exportReport());

        topPanel.add(leftPanel, BorderLayout.WEST);
        topPanel.add(btnExport, BorderLayout.EAST);
        add(topPanel, BorderLayout.NORTH);

        // --- Center Text Area ---
        reportTextArea = new JTextArea();
        reportTextArea.setFont(UIHelper.FONT_MONO);
        reportTextArea.setEditable(false);
        reportTextArea.setBackground(Color.WHITE);
        reportTextArea.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JScrollPane scroll = new JScrollPane(reportTextArea);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(222, 226, 230)));
        add(scroll, BorderLayout.CENTER);
    }

    public void refreshPanel() {
        scanSelector.removeAllItems();
        List<Scan> scans = context.getScanDAO().findAllOrderedByIdDesc();
        if (scans.isEmpty()) {
            scanSelector.addItem("No scans completed yet");
            reportTextArea.setText("No scan reports available. Run a security scan to generate reports.");
            btnExport.setEnabled(false);
            return;
        }

        btnExport.setEnabled(true);
        for (Scan s : scans) {
            scanSelector.addItem("Scan #" + s.getId() + " (" + s.getStartedAt() + ") [" + s.getStatus() + "]");
        }
        scanSelector.setSelectedIndex(0);
        loadSelectedReport();
    }

    private void loadSelectedReport() {
        int idx = scanSelector.getSelectedIndex();
        if (idx < 0) return;

        List<Scan> scans = context.getScanDAO().findAllOrderedByIdDesc();
        if (idx >= scans.size()) return;

        Scan scan = scans.get(idx);
        var events = context.getEventDAO().findByScanId(scan.getId());
        var anomalies = context.getAnomalyDAO().findByScanId(scan.getId());
        var chain = context.getAuditService().verifyChain();
        var trail = context.getAuditService().getAuditTrail();

        String report = context.getReportGenerator().buildReportText(scan, events, anomalies, chain, trail);
        reportTextArea.setText(report);
        reportTextArea.setCaretPosition(0);
    }

    private void exportReport() {
        int idx = scanSelector.getSelectedIndex();
        if (idx < 0) return;

        List<Scan> scans = context.getScanDAO().findAllOrderedByIdDesc();
        if (idx >= scans.size()) return;

        Scan scan = scans.get(idx);

        JFileChooser chooser = new JFileChooser(".");
        chooser.setSelectedFile(new File("FORENSIX-AuditReport-Scan-" + scan.getId() + ".txt"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try {
                Files.writeString(target.toPath(), reportTextArea.getText(), StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this,
                        "Report exported successfully to:\n" + target.getAbsolutePath(),
                        "Export Succeeded", JOptionPane.INFORMATION_MESSAGE);
                mainWindow.setStatus("Report exported to: " + target.getName());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                        "Failed to export report: " + e.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
