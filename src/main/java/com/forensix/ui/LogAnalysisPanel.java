package com.forensix.ui;

import com.forensix.model.Anomaly;
import com.forensix.model.LogEntry;
import com.forensix.model.Scan;
import com.forensix.service.ServiceContext;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Log analysis panel for detecting authentication and system log anomalies.
 */
public class LogAnalysisPanel extends JPanel {

    private final ServiceContext context;
    private final MainWindow mainWindow;

    private JTextField logPathField;
    private JButton btnBrowse;
    private JButton btnAnalyze;
    private JLabel summaryLabel;
    private JTextField filterField;

    private JTable anomalyTable;
    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> sorter;

    public LogAnalysisPanel(ServiceContext context, MainWindow mainWindow) {
        this.context = context;
        this.mainWindow = mainWindow;
        setLayout(new BorderLayout(15, 15));
        setBackground(UIHelper.BG_COLOR);
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        initComponents();
        refreshPanel();
    }

    private void initComponents() {
        // --- Top: Log Path & Action ---
        JPanel topContainer = new JPanel(new BorderLayout(10, 10));
        topContainer.setOpaque(false);

        JPanel fileChooserPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        fileChooserPanel.setOpaque(false);

        fileChooserPanel.add(new JLabel("Log File:"));
        logPathField = new JTextField(context.getConfig().getLogFilePath(), 28);
        logPathField.setFont(UIHelper.FONT_BODY);
        fileChooserPanel.add(logPathField);

        btnBrowse = UIHelper.createStyledButton("Browse...", UIHelper.SECONDARY_COLOR);
        btnBrowse.addActionListener(e -> browseLogFile());
        fileChooserPanel.add(btnBrowse);

        btnAnalyze = UIHelper.createStyledButton("Analyze Logs", UIHelper.PRIMARY_COLOR);
        btnAnalyze.addActionListener(e -> runAnalysis());
        fileChooserPanel.add(btnAnalyze);

        JPanel rightFilterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        rightFilterPanel.setOpaque(false);
        rightFilterPanel.add(new JLabel("Filter:"));
        filterField = new JTextField(12);
        filterField.setFont(UIHelper.FONT_BODY);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
        });
        rightFilterPanel.add(filterField);

        topContainer.add(fileChooserPanel, BorderLayout.WEST);
        topContainer.add(rightFilterPanel, BorderLayout.EAST);
        add(topContainer, BorderLayout.NORTH);

        // --- Center Table ---
        String[] cols = {"Severity", "Rule Triggered", "Raw Log Entry", "Timestamp"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        anomalyTable = new JTable(tableModel);
        anomalyTable.setFont(UIHelper.FONT_BODY);
        anomalyTable.setRowHeight(26);
        anomalyTable.getTableHeader().setFont(UIHelper.FONT_BOLD);
        anomalyTable.getTableHeader().setBackground(UIHelper.BG_COLOR);

        sorter = new TableRowSorter<>(tableModel);
        anomalyTable.setRowSorter(sorter);

        // Severity Color Renderer
        anomalyTable.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value != null) {
                    String sev = value.toString();
                    setFont(UIHelper.FONT_BOLD);
                    if ("CRITICAL".equals(sev)) {
                        setForeground(UIHelper.DANGER_COLOR);
                    } else if ("HIGH".equals(sev)) {
                        setForeground(UIHelper.WARNING_COLOR);
                    } else if ("MEDIUM".equals(sev)) {
                        setForeground(UIHelper.SECONDARY_COLOR);
                    } else {
                        setForeground(UIHelper.TEXT_MUTED);
                    }
                }
                return c;
            }
        });

        JScrollPane scroll = new JScrollPane(anomalyTable);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(222, 226, 230)));
        add(scroll, BorderLayout.CENTER);

        // Bottom status summary
        summaryLabel = new JLabel("Total Anomalies: 0 (Critical: 0, High: 0, Medium: 0, Low: 0)");
        summaryLabel.setFont(UIHelper.FONT_BOLD);
        summaryLabel.setForeground(UIHelper.PRIMARY_COLOR);
        add(summaryLabel, BorderLayout.SOUTH);
    }

    private void filter() {
        String text = filterField.getText().trim();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        }
    }

    private void browseLogFile() {
        JFileChooser chooser = new JFileChooser(".");
        chooser.setDialogTitle("Select Target Log File");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            logPathField.setText(selected.getAbsolutePath());
            context.getConfig().setLogFilePath(selected.getAbsolutePath());
        }
    }

    private void runAnalysis() {
        String pathStr = logPathField.getText().trim();
        if (pathStr.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please specify a log file path.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Path path = Paths.get(pathStr);
        if (!java.nio.file.Files.exists(path)) {
            JOptionPane.showMessageDialog(this, "Log file does not exist: " + pathStr, "File Not Found", JOptionPane.ERROR_MESSAGE);
            return;
        }

        btnAnalyze.setEnabled(false);
        mainWindow.setStatus("Analyzing log entries for security anomalies...");

        SwingWorker<List<Anomaly>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<Anomaly> doInBackground() {
                List<LogEntry> entries = context.getLogAnalyzer().parse(path);
                Scan lastScan = context.getScanDAO().getLastScan();
                long scanId = (lastScan != null) ? lastScan.getId() : 0;
                return context.getLogAnalyzer().evaluate(entries, scanId);
            }

            @Override
            protected void done() {
                btnAnalyze.setEnabled(true);
                try {
                    List<Anomaly> anomalies = get();
                    mainWindow.setStatus("Log analysis finished: " + anomalies.size() + " anomalies detected.");
                    populateTable(anomalies);
                    mainWindow.notifyAllPanelsRefresh();
                } catch (Exception e) {
                    mainWindow.setStatus("Log analysis failed.");
                    JOptionPane.showMessageDialog(LogAnalysisPanel.this,
                            "Log analysis failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    public void refreshPanel() {
        List<Anomaly> all = context.getAnomalyDAO().findAll();
        populateTable(all);
    }

    private void populateTable(List<Anomaly> anomalies) {
        tableModel.setRowCount(0);
        int crit = 0, high = 0, med = 0, low = 0;

        for (Anomaly a : anomalies) {
            tableModel.addRow(new Object[]{
                    a.getSeverity().name(),
                    a.getRuleTriggered(),
                    a.getLogEntry(),
                    a.getDetectedAt()
            });

            if (a.getSeverity() == Anomaly.Severity.CRITICAL) crit++;
            else if (a.getSeverity() == Anomaly.Severity.HIGH) high++;
            else if (a.getSeverity() == Anomaly.Severity.MEDIUM) med++;
            else low++;
        }

        summaryLabel.setText(String.format("Total Anomalies: %d (Critical: %d, High: %d, Medium: %d, Low: %d)",
                anomalies.size(), crit, high, med, low));
    }
}
