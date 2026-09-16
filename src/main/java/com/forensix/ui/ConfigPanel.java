package com.forensix.ui;

import com.forensix.model.Config;
import com.forensix.service.ServiceContext;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Configuration panel for tuning FIM parameters, anomaly detection thresholds,
 * and managing the background scheduler.
 */
public class ConfigPanel extends JPanel {

    private final ServiceContext context;
    private final MainWindow mainWindow;

    private JTextField dirField;
    private JTextField logField;
    private JSpinner thresholdSpinner;
    private JSpinner windowSpinner;
    private JTextField startHoursField;
    private JTextField endHoursField;
    private JTextField blacklistField;
    private JTextField suspiciousUsersField;
    private JSpinner intervalSpinner;
    private JButton btnToggleScheduler;

    public ConfigPanel(ServiceContext context, MainWindow mainWindow) {
        this.context = context;
        this.mainWindow = mainWindow;
        setLayout(new BorderLayout(15, 15));
        setBackground(UIHelper.BG_COLOR);
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        initComponents();
    }

    private void initComponents() {
        Config cfg = context.getConfig();

        JPanel formCard = UIHelper.createCardPanel();
        formCard.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Title
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 3;
        JLabel title = new JLabel("System & Detection Configuration");
        title.setFont(UIHelper.FONT_TITLE);
        title.setForeground(UIHelper.PRIMARY_COLOR);
        formCard.add(title, gbc);

        // Section 1: Monitored Directory
        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Monitored Directory:"), gbc);

        dirField = new JTextField(cfg.getMonitoredDirectory(), 30);
        dirField.setFont(UIHelper.FONT_BODY);
        gbc.gridx = 1; gbc.gridy = row;
        formCard.add(dirField, gbc);

        JButton browseDir = UIHelper.createStyledButton("Browse...", UIHelper.SECONDARY_COLOR);
        browseDir.addActionListener(e -> browseDirectory());
        gbc.gridx = 2; gbc.gridy = row++;
        formCard.add(browseDir, gbc);

        // Section 2: Log File Path
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Target Log File:"), gbc);

        logField = new JTextField(cfg.getLogFilePath(), 30);
        logField.setFont(UIHelper.FONT_BODY);
        gbc.gridx = 1; gbc.gridy = row;
        formCard.add(logField, gbc);

        JButton browseLog = UIHelper.createStyledButton("Browse...", UIHelper.SECONDARY_COLOR);
        browseLog.addActionListener(e -> browseLogFile());
        gbc.gridx = 2; gbc.gridy = row++;
        formCard.add(browseLog, gbc);

        // Section 3: Failed Login Threshold & Window
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Failed Login Threshold:"), gbc);
        thresholdSpinner = new JSpinner(new SpinnerNumberModel(cfg.getFailedLoginThreshold(), 1, 100, 1));
        gbc.gridx = 1; gbc.gridy = row++;
        formCard.add(thresholdSpinner, gbc);

        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Sliding Window (Minutes):"), gbc);
        windowSpinner = new JSpinner(new SpinnerNumberModel(cfg.getTimeWindowMinutes(), 1, 60, 1));
        gbc.gridx = 1; gbc.gridy = row++;
        formCard.add(windowSpinner, gbc);

        // Section 4: Business Hours
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Working Hours Start (HH:mm):"), gbc);
        startHoursField = new JTextField(cfg.getBusinessHoursStart(), 10);
        gbc.gridx = 1; gbc.gridy = row++;
        formCard.add(startHoursField, gbc);

        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Working Hours End (HH:mm):"), gbc);
        endHoursField = new JTextField(cfg.getBusinessHoursEnd(), 10);
        gbc.gridx = 1; gbc.gridy = row++;
        formCard.add(endHoursField, gbc);

        // Section 5: Blacklisted IPs
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Threat Blacklist IPs:"), gbc);
        blacklistField = new JTextField(cfg.getBlacklistedIps(), 30);
        gbc.gridx = 1; gbc.gridy = row++;
        formCard.add(blacklistField, gbc);

        // Section 6: Suspicious Accounts
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Monitored Suspicious Accounts:"), gbc);
        suspiciousUsersField = new JTextField(cfg.getSuspiciousUsers(), 30);
        gbc.gridx = 1; gbc.gridy = row++;
        formCard.add(suspiciousUsersField, gbc);

        // Section 7: Scheduler Interval & Toggle
        gbc.gridx = 0; gbc.gridy = row;
        formCard.add(new JLabel("Background Scan Interval (sec):"), gbc);
        intervalSpinner = new JSpinner(new SpinnerNumberModel(cfg.getScanIntervalSeconds(), 10, 3600, 10));
        gbc.gridx = 1; gbc.gridy = row;
        formCard.add(intervalSpinner, gbc);

        btnToggleScheduler = UIHelper.createStyledButton("Start Scheduler", UIHelper.SUCCESS_COLOR);
        btnToggleScheduler.addActionListener(e -> toggleScheduler());
        gbc.gridx = 2; gbc.gridy = row++;
        formCard.add(btnToggleScheduler, gbc);

        // Section 8: Save Action
        gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 3;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 15));
        btnPanel.setOpaque(false);

        JButton btnSave = UIHelper.createStyledButton("Save Configuration", UIHelper.PRIMARY_COLOR);
        btnSave.addActionListener(e -> saveConfiguration());
        btnPanel.add(btnSave);

        JButton btnReset = UIHelper.createStyledButton("Reload Defaults", UIHelper.WARNING_COLOR);
        btnReset.addActionListener(e -> reloadDefaults());
        btnPanel.add(btnReset);

        formCard.add(btnPanel, gbc);

        JScrollPane scroll = new JScrollPane(formCard);
        scroll.setBorder(null);
        add(scroll, BorderLayout.CENTER);
    }

    private void browseDirectory() {
        JFileChooser chooser = new JFileChooser(".");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Choose Monitored Directory");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            dirField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void browseLogFile() {
        JFileChooser chooser = new JFileChooser(".");
        chooser.setDialogTitle("Choose Log File");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            logField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void saveConfiguration() {
        try {
            Config cfg = context.getConfig();
            cfg.setMonitoredDirectory(dirField.getText().trim());
            cfg.setLogFilePath(logField.getText().trim());
            cfg.setFailedLoginThreshold((Integer) thresholdSpinner.getValue());
            cfg.setTimeWindowMinutes((Integer) windowSpinner.getValue());
            cfg.setBusinessHoursStart(startHoursField.getText().trim());
            cfg.setBusinessHoursEnd(endHoursField.getText().trim());
            cfg.setBlacklistedIps(blacklistField.getText().trim());
            cfg.setSuspiciousUsers(suspiciousUsersField.getText().trim());
            cfg.setScanIntervalSeconds((Integer) intervalSpinner.getValue());

            context.getConfigLoader().saveConfig(cfg);

            // Update running service parameters
            if (context.getLogAnalyzer() instanceof com.forensix.service.LogAnalyzerImpl impl) {
                impl.setFailedLoginThreshold(cfg.getFailedLoginThreshold());
                impl.setTimeWindowMinutes(cfg.getTimeWindowMinutes());
                impl.setBusinessHours(cfg.getParsedBusinessStart(), cfg.getParsedBusinessEnd());
                impl.setBlacklistedIps(cfg.getBlacklistedIpsSet());
                impl.setSuspiciousUsers(cfg.getSuspiciousUsersSet());
            }

            JOptionPane.showMessageDialog(this, "Configuration saved successfully.", "Saved", JOptionPane.INFORMATION_MESSAGE);
            mainWindow.setStatus("Configuration updated.");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error saving configuration: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void reloadDefaults() {
        Config def = new Config();
        dirField.setText(def.getMonitoredDirectory());
        logField.setText(def.getLogFilePath());
        thresholdSpinner.setValue(def.getFailedLoginThreshold());
        windowSpinner.setValue(def.getTimeWindowMinutes());
        startHoursField.setText(def.getBusinessHoursStart());
        endHoursField.setText(def.getBusinessHoursEnd());
        blacklistField.setText(def.getBlacklistedIps());
        suspiciousUsersField.setText(def.getSuspiciousUsers());
        intervalSpinner.setValue(def.getScanIntervalSeconds());
    }

    private void toggleScheduler() {
        var scheduler = context.getScanScheduler();
        if (scheduler.isRunning()) {
            scheduler.stop();
            btnToggleScheduler.setText("Start Scheduler");
            btnToggleScheduler.setBackground(UIHelper.SUCCESS_COLOR);
            mainWindow.setStatus("Scheduler stopped.");
        } else {
            int interval = (Integer) intervalSpinner.getValue();
            scheduler.start(interval, () -> {
                try {
                    Path dir = Paths.get(context.getConfig().getMonitoredDirectory());
                    Path log = Paths.get(context.getConfig().getLogFilePath());
                    context.executeFullScan(dir, log);
                    mainWindow.notifyAllPanelsRefresh();
                } catch (Exception e) {
                    System.err.println("Scheduled scan error: " + e.getMessage());
                }
            });
            btnToggleScheduler.setText("Stop Scheduler");
            btnToggleScheduler.setBackground(UIHelper.DANGER_COLOR);
            mainWindow.setStatus("Background scheduler active (" + interval + "s interval).");
        }
    }
}
