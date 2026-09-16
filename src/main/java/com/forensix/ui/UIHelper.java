package com.forensix.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.Border;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;

/**
 * UI styling constants and component factories for a modern, cohesive desktop interface.
 */
public final class UIHelper {

    // Color Palette
    public static final Color PRIMARY_COLOR = new Color(24, 43, 73);       // Deep Navy
    public static final Color SECONDARY_COLOR = new Color(41, 128, 185);   // Steel Blue
    public static final Color ACCENT_COLOR = new Color(52, 152, 219);      // Bright Blue
    public static final Color SUCCESS_COLOR = new Color(39, 174, 96);      // Emerald Green
    public static final Color WARNING_COLOR = new Color(243, 156, 18);     // Amber Orange
    public static final Color DANGER_COLOR = new Color(192, 57, 43);       // Crimson Red
    public static final Color BG_COLOR = new Color(245, 247, 250);         // Off-White/Light Gray
    public static final Color CARD_BG = Color.WHITE;
    public static final Color TEXT_PRIMARY = new Color(33, 37, 41);
    public static final Color TEXT_MUTED = new Color(108, 117, 125);

    // Fonts
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 18);
    public static final Font FONT_HEADER = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_BOLD = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 12);

    private UIHelper() {}

    public static JButton createStyledButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_BOLD);
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(bg.darker(), 1),
                BorderFactory.createEmptyBorder(8, 16, 8, 16)
        ));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    public static JPanel createCardPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(CARD_BG);
        Border line = BorderFactory.createLineBorder(new Color(222, 226, 230), 1);
        Border padding = BorderFactory.createEmptyBorder(12, 16, 12, 16);
        panel.setBorder(BorderFactory.createCompoundBorder(line, padding));
        return panel;
    }

    public static JPanel createMetricCard(String title, String initialValue, Color accent) {
        JPanel card = createCardPanel();
        card.setLayout(new java.awt.BorderLayout(5, 5));
        card.setPreferredSize(new Dimension(180, 80));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(FONT_SMALL);
        titleLabel.setForeground(TEXT_MUTED);

        JLabel valueLabel = new JLabel(initialValue);
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        valueLabel.setForeground(accent);

        card.add(titleLabel, java.awt.BorderLayout.NORTH);
        card.add(valueLabel, java.awt.BorderLayout.CENTER);
        return card;
    }
}
