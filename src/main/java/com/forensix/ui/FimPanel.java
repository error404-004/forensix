package com.forensix.ui;

import com.forensix.model.FileEvent;
import com.forensix.model.Scan;
import com.forensix.service.ServiceContext;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;

/**
 * File Integrity Monitoring (FIM) panel displaying scan history and detailed diffs.
 */
public class FimPanel extends JPanel {

    private final ServiceContext context;
    private final MainWindow mainWindow;

    private JComboBox<String> scanSelector;
    private JLabel summaryLabel;
    private JTextField searchField;
    private JTable eventTable;
    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> sorter;

    public FimPanel(ServiceContext context, MainWindow mainWindow) {
        this.context = context;
        this.mainWindow = mainWindow;
        setLayout(new BorderLayout(15, 15));
        setBackground(UIHelper.BG_COLOR);
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        initComponents();
        refreshPanel();
    }

    private void initComponents() {
        // --- Header / Controls ---
        JPanel topContainer = new JPanel(new BorderLayout(10, 10));
        topContainer.setOpaque(false);

        JPanel leftControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        leftControls.setOpaque(false);

        leftControls.add(new JLabel("Select Scan:"));
        scanSelector = new JComboBox<>();
        scanSelector.setFont(UIHelper.FONT_BODY);
        scanSelector.addActionListener(e -> onScanSelected());
        leftControls.add(scanSelector);

        leftControls.add(new JLabel("Filter:"));
        searchField = new JTextField(15);
        searchField.setFont(UIHelper.FONT_BODY);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
        });
        leftControls.add(searchField);

        summaryLabel = new JLabel("Files: 0 | Changes: 0");
        summaryLabel.setFont(UIHelper.FONT_BOLD);
        summaryLabel.setForeground(UIHelper.PRIMARY_COLOR);

        topContainer.add(leftControls, BorderLayout.WEST);
        topContainer.add(summaryLabel, BorderLayout.EAST);
        add(topContainer, BorderLayout.NORTH);

        // --- Center Table ---
        String[] cols = {"Event Type", "Relative File Path", "Previous Hash (SHA-256)", "Current Hash (SHA-256)", "Detected At"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        eventTable = new JTable(tableModel);
        eventTable.setFont(UIHelper.FONT_BODY);
        eventTable.setRowHeight(26);
        eventTable.getTableHeader().setFont(UIHelper.FONT_BOLD);
        eventTable.getTableHeader().setBackground(UIHelper.BG_COLOR);

        sorter = new TableRowSorter<>(tableModel);
        eventTable.setRowSorter(sorter);

        // Custom Cell Renderer for Event Types
        eventTable.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value != null) {
                    String status = value.toString();
                    setFont(UIHelper.FONT_BOLD);
                    if ("MODIFIED".equals(status)) {
                        setForeground(UIHelper.WARNING_COLOR);
                    } else if ("ADDED".equals(status)) {
                        setForeground(UIHelper.SUCCESS_COLOR);
                    } else if ("DELETED".equals(status)) {
                        setForeground(UIHelper.DANGER_COLOR);
                    } else if ("SCAN_ERROR".equals(status)) {
                        setForeground(Color.RED);
                    } else {
                        setForeground(UIHelper.TEXT_MUTED);
                    }
                }
                return c;
            }
        });

        // Mono font for hashes
        DefaultTableCellRenderer monoRenderer = new DefaultTableCellRenderer();
        monoRenderer.setFont(UIHelper.FONT_MONO);
        eventTable.getColumnModel().getColumn(2).setCellRenderer(monoRenderer);
        eventTable.getColumnModel().getColumn(3).setCellRenderer(monoRenderer);

        JScrollPane scroll = new JScrollPane(eventTable);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(222, 226, 230)));
        add(scroll, BorderLayout.CENTER);
    }

    private void filter() {
        String text = searchField.getText().trim();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
        }
    }

    public void refreshPanel() {
        scanSelector.removeAllItems();
        List<Scan> scans = context.getScanDAO().findAllOrderedByIdDesc();
        if (scans.isEmpty()) {
            scanSelector.addItem("No scans available");
            tableModel.setRowCount(0);
            summaryLabel.setText("Files: 0 | Changes: 0");
            return;
        }

        for (Scan s : scans) {
            scanSelector.addItem("Scan #" + s.getId() + " — " + s.getStartedAt() + " [" + s.getStatus() + "]");
        }
        scanSelector.setSelectedIndex(0);
        onScanSelected();
    }

    private void onScanSelected() {
        int idx = scanSelector.getSelectedIndex();
        if (idx < 0) return;

        List<Scan> scans = context.getScanDAO().findAllOrderedByIdDesc();
        if (idx >= scans.size()) return;

        Scan scan = scans.get(idx);
        List<FileEvent> events = context.getEventDAO().findByScanId(scan.getId());

        tableModel.setRowCount(0);
        int added = 0, modified = 0, deleted = 0, unchanged = 0, errors = 0;

        for (FileEvent e : events) {
            tableModel.addRow(new Object[]{
                    e.getEventType().name(),
                    e.getPath(),
                    e.getOldHash() != null ? e.getOldHash() : "-",
                    e.getNewHash() != null ? e.getNewHash() : "-",
                    e.getDetectedAt()
            });

            if (e.getEventType() == FileEvent.EventType.ADDED) added++;
            else if (e.getEventType() == FileEvent.EventType.MODIFIED) modified++;
            else if (e.getEventType() == FileEvent.EventType.DELETED) deleted++;
            else if (e.getEventType() == FileEvent.EventType.SCAN_ERROR) errors++;
            else unchanged++;
        }

        summaryLabel.setText(String.format("Total: %d | Unchanged: %d | Added: %d | Modified: %d | Deleted: %d | Errors: %d",
                events.size(), unchanged, added, modified, deleted, errors));
    }
}
