package com.forensix.ui;

import com.forensix.model.AuditRecord;
import com.forensix.service.ServiceContext;
import com.forensix.service.VerificationResult;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;

/**
 * Audit Trail panel showing the tamper-evident cryptographic hash chain
 * and providing one-click integrity verification with broken link pinpointing.
 */
public class AuditPanel extends JPanel {

    private final ServiceContext context;
    private final MainWindow mainWindow;

    private JPanel statusBanner;
    private JLabel statusBannerText;
    private JButton btnVerify;

    private JTable auditTable;
    private DefaultTableModel tableModel;
    private JTextArea detailArea;

    private List<AuditRecord> cachedRecords;

    public AuditPanel(ServiceContext context, MainWindow mainWindow) {
        this.context = context;
        this.mainWindow = mainWindow;
        setLayout(new BorderLayout(15, 15));
        setBackground(UIHelper.BG_COLOR);
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        initComponents();
        refreshPanel();
    }

    private void initComponents() {
        // --- Top: Verification Action & Banner ---
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setOpaque(false);

        JPanel actionRow = new JPanel(new BorderLayout());
        actionRow.setOpaque(false);

        JLabel lblTitle = new JLabel("Tamper-Evident Cryptographic Audit Trail");
        lblTitle.setFont(UIHelper.FONT_TITLE);
        lblTitle.setForeground(UIHelper.PRIMARY_COLOR);

        btnVerify = UIHelper.createStyledButton("Verify Cryptographic Chain", UIHelper.PRIMARY_COLOR);
        btnVerify.addActionListener(e -> runVerification());

        actionRow.add(lblTitle, BorderLayout.WEST);
        actionRow.add(btnVerify, BorderLayout.EAST);

        topPanel.add(actionRow);
        topPanel.add(Box.createVerticalStrut(10));

        // Status Banner
        statusBanner = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 12));
        statusBanner.setBackground(Color.WHITE);
        statusBanner.setBorder(BorderFactory.createLineBorder(new Color(222, 226, 230), 2));

        statusBannerText = new JLabel("Status: Audit chain integrity not yet verified in this view.");
        statusBannerText.setFont(new Font("Segoe UI", Font.BOLD, 13));
        statusBannerText.setForeground(UIHelper.TEXT_PRIMARY);
        statusBanner.add(statusBannerText);

        topPanel.add(statusBanner);
        add(topPanel, BorderLayout.NORTH);

        // --- Center: Split Pane with Table on Top and Details on Bottom ---
        String[] cols = {"ID", "Record Type", "Ref ID", "Payload Preview", "Prev Hash", "Sealed Hash", "Timestamp"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        auditTable = new JTable(tableModel);
        auditTable.setFont(UIHelper.FONT_BODY);
        auditTable.setRowHeight(24);
        auditTable.getTableHeader().setFont(UIHelper.FONT_BOLD);
        auditTable.getTableHeader().setBackground(UIHelper.BG_COLOR);
        auditTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Mono font for hashes
        DefaultTableCellRenderer monoRenderer = new DefaultTableCellRenderer();
        monoRenderer.setFont(UIHelper.FONT_MONO);
        auditTable.getColumnModel().getColumn(4).setCellRenderer(monoRenderer);
        auditTable.getColumnModel().getColumn(5).setCellRenderer(monoRenderer);

        auditTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showRecordDetails();
            }
        });

        JScrollPane tableScroll = new JScrollPane(auditTable);
        tableScroll.setBorder(BorderFactory.createLineBorder(new Color(222, 226, 230)));

        detailArea = new JTextArea();
        detailArea.setFont(UIHelper.FONT_MONO);
        detailArea.setEditable(false);
        detailArea.setBackground(new Color(250, 250, 252));
        detailArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        detailArea.setText("Select an audit record above to view its canonical payload and cryptographic signature.");

        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Cryptographic Record Inspection"));
        detailScroll.setPreferredSize(new Dimension(800, 150));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        splitPane.setResizeWeight(0.7);
        splitPane.setDividerSize(6);

        add(splitPane, BorderLayout.CENTER);
    }

    public void runVerification() {
        mainWindow.setStatus("Verifying cryptographic audit chain integrity...");
        VerificationResult result = context.getAuditService().verifyChain();

        if (result.isValid()) {
            statusBanner.setBackground(new Color(235, 247, 238));
            statusBanner.setBorder(BorderFactory.createLineBorder(UIHelper.SUCCESS_COLOR, 2));
            statusBannerText.setText("CHAIN INTACT [VALID]: " + result.getMessage());
            statusBannerText.setForeground(UIHelper.SUCCESS_COLOR);
            mainWindow.setStatus("Audit chain verified clean (" + result.getTotalRecordsVerified() + " records checked).");
        } else {
            statusBanner.setBackground(new Color(253, 237, 236));
            statusBanner.setBorder(BorderFactory.createLineBorder(UIHelper.DANGER_COLOR, 2));
            statusBannerText.setText(String.format("TAMPERING DETECTED! Broken Record: #%d (%s) — Altered outside application!",
                    result.getBrokenRecordId(), result.getBrokenField()));
            statusBannerText.setForeground(UIHelper.DANGER_COLOR);
            mainWindow.setStatus("ALERT: Audit chain tampering detected at record #" + result.getBrokenRecordId());
        }

        refreshPanel();
    }

    public void refreshPanel() {
        cachedRecords = context.getAuditService().getAuditTrail();
        tableModel.setRowCount(0);

        for (AuditRecord r : cachedRecords) {
            String prevTrunc = (r.getPrevHash() != null && r.getPrevHash().length() > 12)
                    ? r.getPrevHash().substring(0, 12) + "..." : r.getPrevHash();
            String hashTrunc = (r.getRecordHash() != null && r.getRecordHash().length() > 12)
                    ? r.getRecordHash().substring(0, 12) + "..." : r.getRecordHash();
            String payloadPreview = (r.getPayload() != null && r.getPayload().length() > 40)
                    ? r.getPayload().substring(0, 40) + "..." : r.getPayload();

            tableModel.addRow(new Object[]{
                    r.getId(),
                    r.getRecordType().name(),
                    r.getRecordRefId(),
                    payloadPreview,
                    prevTrunc,
                    hashTrunc,
                    r.getCreatedAt()
            });
        }
    }

    private void showRecordDetails() {
        int row = auditTable.getSelectedRow();
        if (row < 0 || cachedRecords == null || row >= cachedRecords.size()) return;

        AuditRecord r = cachedRecords.get(row);
        StringBuilder sb = new StringBuilder();
        sb.append("=== AUDIT RECORD #").append(r.getId()).append(" DETAILS ===\n");
        sb.append("Type              : ").append(r.getRecordType()).append("\n");
        sb.append("Reference ID      : ").append(r.getRecordRefId()).append("\n");
        sb.append("Created At        : ").append(r.getCreatedAt()).append("\n");
        sb.append("Previous Hash     : ").append(r.getPrevHash()).append("\n");
        sb.append("Record Hash       : ").append(r.getRecordHash()).append("\n");
        sb.append("Canonical String  : ").append(r.getCanonicalData()).append("\n");
        sb.append("Formula           : SHA256(canonical_data + '|' + prev_hash)\n");
        sb.append("Payload           : ").append(r.getPayload()).append("\n");

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }
}
