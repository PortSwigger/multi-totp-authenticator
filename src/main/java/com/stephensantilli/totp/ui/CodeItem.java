package com.stephensantilli.totp.ui;

import static com.stephensantilli.totp.TOTP.api;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import com.stephensantilli.totp.Code;
import com.stephensantilli.totp.CodeListener;

import burp.api.montoya.ui.Theme;

public class CodeItem extends JPanel implements KeyListener, MouseListener {

    private Code code;

    private JLabel nameLbl, algoLbl, codeLbl, matchLbl;

    private JButton copyBtn, removeBtn;

    private JTextField matchField;

    private JProgressBar progressBar;

    private CodeListener listener;

    private JCheckBox enabledBox;

    private Insets insets;

    private Font font;

    public CodeItem(Code code, CodeListener listener) {

        this.code = code;
        this.listener = listener;

        setLayout(new GridBagLayout());

        this.font = api.userInterface().currentDisplayFont();
        font = font.deriveFont(font.getSize() * 1.5f);

        int inset = 10;
        this.insets = new Insets(inset, inset, inset, inset);

        createMatchComponents();
        createCodeDisplay();
        createButtons();

        addMouseListener(this);

        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 250));

    }

    public String formatCrypto(String crypto) {

        if (crypto.equals("HmacSHA256"))
            return "SHA-256";
        else if (crypto.equals("HmacSHA512"))
            return "SHA-512";
        else if (crypto.equals("HmacSHA1"))
            return "SHA-1";
        else
            return crypto;

    }

    public String formatCode(String code) {

        int len = code.length();

        if (len % 2 == 0)
            return code.substring(0, len / 2) + " " + code.substring(len / 2, len);
        else if (len == 9)
            return code.substring(0, 3) + " " + code.substring(3, 6) + " " + code.substring(6, 9);
        else
            return code;

    }

    public void updateCode() {

        String value = code.generateCode();

        codeLbl.setText(formatCode(value));
        codeLbl.setToolTipText(value);

        updateProgressBar();

    }

    public void setRegexValid(boolean b) {

        boolean darkMode = api.userInterface().currentTheme() == Theme.DARK;
        Color normal = darkMode ? new Color(0, 0, 0, 0) : Color.LIGHT_GRAY;

        Border lineBorder = BorderFactory.createLineBorder(b ? normal : Color.RED, 1);
        Border margin = new EmptyBorder(5, 5, 5, 5);

        matchField.setBorder(new CompoundBorder(lineBorder, margin));

    }

    @Override
    public void keyTyped(KeyEvent e) {

        SwingUtilities.invokeLater(() -> {

            listener.matchUpdate(code, matchField.getText());

        });

    }

    @Override
    public void mouseEntered(MouseEvent e) {

        boolean darkMode = api.userInterface().currentTheme() == Theme.DARK;
        setBackground(darkMode ? Color.DARK_GRAY : new Color(240, 240, 240, 250));

    }

    @Override
    public void mouseExited(MouseEvent e) {

        setBackground(null);

    }

    public Code getCode() {

        return code;
    }

    public JLabel getNameLbl() {

        return nameLbl;
    }

    public JLabel getAlgoLbl() {

        return algoLbl;
    }

    public JLabel getCodeLbl() {

        return codeLbl;
    }

    public JButton getRemoveBtn() {

        return removeBtn;
    }

    public CodeListener getListener() {

        return listener;
    }

    @Override
    public void keyPressed(KeyEvent e) {

    }

    @Override
    public void keyReleased(KeyEvent e) {

    }

    @Override
    public void mouseClicked(MouseEvent e) {

    }

    @Override
    public void mousePressed(MouseEvent e) {

    }

    @Override
    public void mouseReleased(MouseEvent e) {

    }

    private void createCodeDisplay() {

        this.nameLbl = new JLabel(code.getName());
        nameLbl.setFont(font.deriveFont(Font.BOLD));
        nameLbl.addMouseListener(this);
        nameLbl.setToolTipText("Name: " + code.getName());

        GridBagConstraints nameLblCons = new GridBagConstraints();
        nameLblCons.gridx = 0;
        nameLblCons.gridy = 0;
        nameLblCons.weightx = .5;
        nameLblCons.weighty = .5;
        nameLblCons.gridheight = 1;
        nameLblCons.gridwidth = 1;
        nameLblCons.insets = insets;
        nameLblCons.fill = GridBagConstraints.BOTH;
        nameLblCons.anchor = GridBagConstraints.CENTER;

        this.algoLbl = new JLabel(formatCrypto(code.getCrypto()));
        algoLbl.setFont(font.deriveFont(Font.BOLD));
        algoLbl.setForeground(new Color(100, 100, 100));
        algoLbl.addMouseListener(this);
        algoLbl.setToolTipText("Hashing algorithm");
        algoLbl.setHorizontalAlignment(JLabel.RIGHT);

        int inset = insets.top;

        GridBagConstraints algoLblCons = new GridBagConstraints();
        algoLblCons.gridx = 2;
        algoLblCons.gridy = 0;
        algoLblCons.weightx = .25;
        algoLblCons.weighty = .5;
        algoLblCons.gridheight = 1;
        algoLblCons.gridwidth = 1;
        algoLblCons.insets = new Insets(inset, inset, inset, inset * 2);
        algoLblCons.fill = GridBagConstraints.BOTH;
        algoLblCons.anchor = GridBagConstraints.EAST;

        this.codeLbl = new JLabel(formatCode(code.generateCode()));
        codeLbl.setFont(font.deriveFont(Font.BOLD, font.getSize() * 2f));
        codeLbl.addMouseListener(this);
        codeLbl.setToolTipText(code.generateCode());
        codeLbl.setHorizontalAlignment(JLabel.CENTER);

        GridBagConstraints codeLblCons = new GridBagConstraints();
        codeLblCons.gridx = 0;
        codeLblCons.gridy = 1;
        codeLblCons.weightx = .5;
        codeLblCons.weighty = .5;
        codeLblCons.gridheight = 1;
        codeLblCons.gridwidth = 1;
        codeLblCons.insets = insets;
        codeLblCons.fill = GridBagConstraints.BOTH;
        codeLblCons.anchor = GridBagConstraints.CENTER;

        this.progressBar = new JProgressBar(0, code.getDuration());
        progressBar.addMouseListener(this);

        GridBagConstraints progressBarCons = new GridBagConstraints();
        progressBarCons.gridx = 0;
        progressBarCons.gridy = 2;
        progressBarCons.weightx = .5;
        progressBarCons.weighty = .5;
        progressBarCons.gridheight = 1;
        progressBarCons.gridwidth = 1;
        progressBarCons.insets = insets;
        progressBarCons.fill = GridBagConstraints.BOTH;
        progressBarCons.anchor = GridBagConstraints.CENTER;

        this.copyBtn = new JButton("Copy Code");
        copyBtn.setFont(font);
        copyBtn.addMouseListener(this);
        copyBtn.setToolTipText("Copy TOTP to clipboard");

        this.add(nameLbl, nameLblCons);
        this.add(algoLbl, algoLblCons);
        this.add(codeLbl, codeLblCons);
        this.add(progressBar, progressBarCons);

    }

    private void createMatchComponents() {

        this.matchLbl = new JLabel("Match:");
        matchLbl.setFont(font.deriveFont(Font.BOLD));
        matchLbl.addMouseListener(this);
        matchLbl.setEnabled(code.isEnabled());

        GridBagConstraints matchLblCons = new GridBagConstraints();
        matchLblCons.gridx = 1;
        matchLblCons.gridy = 0;
        matchLblCons.weightx = .5;
        matchLblCons.weighty = .5;
        matchLblCons.gridheight = 1;
        matchLblCons.gridwidth = 1;
        matchLblCons.insets = insets;
        matchLblCons.fill = GridBagConstraints.BOTH;
        matchLblCons.anchor = GridBagConstraints.CENTER;

        this.matchField = new JTextField(code.getMatch());
        matchField.setFont(font);
        matchField.addMouseListener(this);
        matchField.addKeyListener(this);
        matchField.setColumns(10);
        matchField.setEnabled(code.isEnabled());

        GridBagConstraints matchFieldCons = new GridBagConstraints();
        matchFieldCons.gridx = 1;
        matchFieldCons.gridy = 1;
        matchFieldCons.weightx = .0;
        matchFieldCons.weighty = .5;
        matchFieldCons.gridheight = 1;
        matchFieldCons.gridwidth = 1;
        matchFieldCons.insets = insets;
        matchFieldCons.fill = GridBagConstraints.BOTH;
        matchFieldCons.anchor = GridBagConstraints.CENTER;

        boolean darkMode = api.userInterface().currentTheme() == Theme.DARK;
        Color normal = darkMode ? new Color(0, 0, 0, 0) : Color.LIGHT_GRAY;
        Border matchFieldLineBorder = BorderFactory.createLineBorder(normal, 1);
        Border matchFieldMarginBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);
        matchField.setBorder(new CompoundBorder(matchFieldLineBorder, matchFieldMarginBorder));

        this.enabledBox = new JCheckBox();
        enabledBox.setFont(font);
        enabledBox.addMouseListener(this);
        enabledBox.setToolTipText("Enable replacing");
        enabledBox.setText("Replace in requests?");
        enabledBox.setSelected(code.isEnabled());

        GridBagConstraints enabledBoxCons = new GridBagConstraints();
        enabledBoxCons.gridx = 1;
        enabledBoxCons.gridy = 2;
        enabledBoxCons.weightx = .5;
        enabledBoxCons.weighty = .5;
        enabledBoxCons.gridheight = 1;
        enabledBoxCons.gridwidth = 1;
        enabledBoxCons.insets = insets;
        enabledBoxCons.fill = GridBagConstraints.BOTH;
        enabledBoxCons.anchor = GridBagConstraints.CENTER;

        enabledBox.addActionListener(l -> {

            boolean enabled = enabledBox.isSelected();

            listener.setEnabled(code, enabled);
            matchField.setEnabled(enabled);
            matchLbl.setEnabled(enabled);

        });

        this.add(matchLbl, matchLblCons);
        this.add(matchField, matchFieldCons);
        this.add(enabledBox, enabledBoxCons);

    }

    private void createButtons() {

        GridBagConstraints copyBtnCons = new GridBagConstraints();
        copyBtnCons.gridx = 2;
        copyBtnCons.gridy = 1;
        copyBtnCons.weightx = .25;
        copyBtnCons.weighty = .5;
        copyBtnCons.gridheight = 1;
        copyBtnCons.gridwidth = 1;
        copyBtnCons.ipadx = 0;
        copyBtnCons.ipady = 10;
        copyBtnCons.insets = insets;
        copyBtnCons.fill = GridBagConstraints.BOTH;
        copyBtnCons.anchor = GridBagConstraints.CENTER;

        Timer delay = new Timer(200, m -> {

            copyBtn.setText("Copy Code");

        });

        delay.setRepeats(false);

        copyBtn.addActionListener(l -> {

            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(code.generateCode()), null);

            copyBtn.setText("✓");

            delay.restart();

        });

        this.removeBtn = new JButton("✕");
        removeBtn.setFont(font);
        removeBtn.addMouseListener(this);

        GridBagConstraints removeBtnCons = new GridBagConstraints();
        removeBtnCons.gridx = 2;
        removeBtnCons.gridy = 2;
        removeBtnCons.weightx = .25;
        removeBtnCons.weighty = .5;
        removeBtnCons.gridheight = 1;
        removeBtnCons.gridwidth = 1;
        removeBtnCons.insets = insets;
        removeBtnCons.ipadx = 0;
        removeBtnCons.ipady = 0;
        removeBtnCons.fill = GridBagConstraints.BOTH;
        removeBtnCons.anchor = GridBagConstraints.CENTER;

        removeBtn.addActionListener(l -> {

            listener.removeCode(this);

        });

        this.add(copyBtn, copyBtnCons);
        this.add(removeBtn, removeBtnCons);

    }

    private void updateProgressBar() {

        int duration = code.getDuration();
        int progress = duration - (((int) (System.currentTimeMillis() / 1000)) % duration);

        progressBar.setValue(progress);

    }

}
