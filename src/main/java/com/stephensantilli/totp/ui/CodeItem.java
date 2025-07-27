package com.stephensantilli.totp.ui;

import static com.stephensantilli.totp.TOTP.api;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
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

    public CodeItem(Code code, CodeListener listener) {

        this.code = code;
        this.listener = listener;

        BoxLayout layout = new BoxLayout(this, BoxLayout.X_AXIS);
        setLayout(layout);

        Font font = api.userInterface().currentDisplayFont();
        font = font.deriveFont(font.getSize() * 2f);

        FontMetrics metrics = getFontMetrics(font);

        int inset = 10;
        Border defaultInsets = BorderFactory.createEmptyBorder(inset, inset, inset, inset);

        this.nameLbl = new JLabel(code.getName());
        nameLbl.setFont(font);
        nameLbl.addMouseListener(this);
        nameLbl.setBorder(defaultInsets);
        nameLbl.setPreferredSize(new Dimension(250, Integer.MAX_VALUE));
        nameLbl.setMinimumSize(new Dimension(100, Integer.MAX_VALUE));
        nameLbl.setMaximumSize(nameLbl.getPreferredSize());

        this.algoLbl = new JLabel(getCryptoDisplay(code.getCrypto()));
        algoLbl.setFont(font);
        algoLbl.addMouseListener(this);
        algoLbl.setBorder(defaultInsets);
        algoLbl.setPreferredSize(new Dimension(metrics.stringWidth("SHA-512") + inset * 2, Integer.MAX_VALUE));
        algoLbl.setMinimumSize(algoLbl.getPreferredSize());
        algoLbl.setMaximumSize(algoLbl.getPreferredSize());

        this.codeLbl = new JLabel(getCodeDisplay(code.generateCode()));
        codeLbl.setFont(font);
        codeLbl.addMouseListener(this);
        codeLbl.setBorder(defaultInsets);
        codeLbl.setPreferredSize(new Dimension(metrics.stringWidth("0000 0000") + inset * 2, Integer.MAX_VALUE));
        codeLbl.setMinimumSize(codeLbl.getPreferredSize());
        codeLbl.setMaximumSize(codeLbl.getPreferredSize());

        this.progressBar = new JProgressBar(0, code.getDuration());
        progressBar.addMouseListener(this);
        progressBar.setBorder(defaultInsets);
        progressBar.setPreferredSize(new Dimension(350, 50));
        progressBar.setMinimumSize(new Dimension(100, 50));
        progressBar.setMaximumSize(progressBar.getPreferredSize());

        this.matchLbl = new JLabel("Match:");
        matchLbl.setFont(font);
        matchLbl.addMouseListener(this);
        matchLbl.setBorder(defaultInsets);
        matchLbl.setHorizontalTextPosition(JLabel.CENTER);

        matchLbl.setEnabled(code.isEnabled());

        this.matchField = new JTextField(code.getMatch());
        matchField.setFont(font);
        matchField.addMouseListener(this);
        matchField.addKeyListener(this);
        matchField.setMargin(new Insets(5, 5, 5, 5));
        matchField.setPreferredSize(new Dimension(450, Integer.MAX_VALUE));
        matchField.setMinimumSize(new Dimension(150, Integer.MAX_VALUE));
        matchField.setMaximumSize(matchField.getPreferredSize());

        matchField.setEnabled(code.isEnabled());

        boolean darkMode = api.userInterface().currentTheme() == Theme.DARK;
        Color normal = darkMode ? new Color(0, 0, 0, 0) : Color.LIGHT_GRAY;

        Border matchFieldLineBorder = BorderFactory.createLineBorder(normal, 1);
        Border matchFieldMarginBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);

        matchField.setBorder(new CompoundBorder(matchFieldLineBorder, matchFieldMarginBorder));

        this.enabledBox = new JCheckBox();
        enabledBox.setFont(font);
        enabledBox.addMouseListener(this);
        enabledBox.setBorder(defaultInsets);
        enabledBox.setToolTipText("Enable replacing");
        enabledBox.setText("Replace in requests?");

        enabledBox.setSelected(code.isEnabled());

        enabledBox.addActionListener(l -> {

            boolean enabled = enabledBox.isSelected();

            listener.setEnabled(code, enabled);
            matchField.setEnabled(enabled);
            matchLbl.setEnabled(enabled);

        });

        this.removeBtn = new JButton("✕");
        removeBtn.setFont(font);
        removeBtn.addMouseListener(this);
        removeBtn.setBorder(new CompoundBorder(removeBtn.getBorder(), defaultInsets));

        removeBtn.addActionListener(l -> {

            listener.removeCode(this);

        });

        this.copyBtn = new JButton("Copy");
        copyBtn.setFont(font);
        copyBtn.addMouseListener(this);
        copyBtn.setBorder(new CompoundBorder(copyBtn.getBorder(), defaultInsets));
        copyBtn.setPreferredSize(new Dimension(metrics.stringWidth("Copy") + 75, Integer.MAX_VALUE));
        copyBtn.setMinimumSize(copyBtn.getPreferredSize());
        copyBtn.setToolTipText("Copy TOTP to clipboard");

        Timer delay = new Timer(200, m -> {

            copyBtn.setText("Copy");

        });

        delay.setRepeats(false);

        copyBtn.addActionListener(l -> {

            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(code.generateCode()), null);

            copyBtn.setText("✓");

            delay.restart();

        });

        addMouseListener(this);
        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));

        this.add(nameLbl);
        this.add(Box.createHorizontalGlue());
        this.add(algoLbl);
        this.add(Box.createHorizontalGlue());
        this.add(codeLbl);
        this.add(Box.createHorizontalGlue());
        this.add(progressBar);
        this.add(Box.createHorizontalGlue());
        this.add(matchLbl);
        this.add(Box.createHorizontalGlue());
        this.add(matchField);
        this.add(Box.createHorizontalGlue());
        this.add(enabledBox);
        this.add(Box.createHorizontalGlue());
        this.add(copyBtn);
        this.add(Box.createHorizontalGlue());
        this.add(Box.createRigidArea(new Dimension(10, 0)));
        this.add(removeBtn);

        setPreferredSize(new Dimension(getWidth(), 130));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, getPreferredSize().height));

        setAlignmentX(Component.LEFT_ALIGNMENT);

    }

    public String getCryptoDisplay(String crypto) {

        if (crypto.equals("HmacSHA256"))
            return "SHA-256";
        else if (crypto.equals("HmacSHA512"))
            return "SHA-512";
        else if (crypto.equals("HmacSHA1"))
            return "SHA-1";
        else
            return crypto;

    }

    public String getCodeDisplay(String code) {

        int len = code.length();

        if (len % 2 == 0)
            return code.substring(0, len / 2) + " " + code.substring(len / 2, len);
        else
            return code;

    }

    private void updateProgressBar() {

        int duration = code.getDuration();
        int progress = duration - (((int) (System.currentTimeMillis() / 1000)) % duration);

        progressBar.setValue(progress);

    }

    public void updateCode() {

        codeLbl.setText(getCodeDisplay(code.generateCode()));
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

        setBackground(
                api.userInterface().currentTheme() == Theme.DARK ? Color.DARK_GRAY : new Color(240, 240, 240, 250));

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

}
