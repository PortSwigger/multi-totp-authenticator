package com.stephensantilli.totp.ui;

import static com.stephensantilli.totp.TOTP.api;
import static com.stephensantilli.totp.TOTP.logOutput;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
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
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;

import org.kordamp.ikonli.materialdesign2.MaterialDesignC;
import org.kordamp.ikonli.materialdesign2.MaterialDesignK;
import org.kordamp.ikonli.materialdesign2.MaterialDesignS;
import org.kordamp.ikonli.swing.FontIcon;

import com.stephensantilli.totp.Code;
import com.stephensantilli.totp.UIListener;

import burp.api.montoya.ui.Theme;

/**
 * The UI element responsible for displaying a single TOTP code that a user has
 * added.
 * 
 * @see CodeTable
 */
public class CodeItem extends JPanel implements KeyListener, MouseListener {

    private Code code;

    private JLabel nameLbl, algoLbl, codeLbl, matchLbl;

    private JButton copyCodeBtn, copySecretBtn, removeBtn;

    private JTextField matchField;

    private JProgressBar progressBar;

    private UIListener listener;

    private JCheckBox enabledBox;

    private Insets insets;

    private Font font;

    private FontIcon copySuccessIcon, copyCodeIcon, copySecretIcon, removeIcon, algoIcon;

    private boolean darkMode, regexValid;

    public CodeItem(Code code, UIListener listener) {

        this.code = code;
        this.listener = listener;
        this.regexValid = false;

        setLayout(new GridBagLayout());

        this.font = api.userInterface().currentDisplayFont();
        font = font.deriveFont(font.getSize() * 1.5f);

        int inset = 10;
        this.insets = new Insets(inset, inset, inset, inset);

        createCodeDisplay();
        createMatchComponents();
        createButtons();

        addMouseListener(this);

        FontMetrics metrics = getFontMetrics(font);

        this.darkMode = api.userInterface().currentTheme() == Theme.DARK;

        // Things get weird if this panel isn't given enough height.
        // At a high enough font size even this isn't enough.
        int maxHeight = metrics.getHeight() + 215;

        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, maxHeight));
        setPreferredSize(new Dimension(getWidth(), maxHeight));

        updateCode();

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

        this.regexValid = b;

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
        setBackground(darkMode ? new Color(57, 57, 57, 250) : new Color(240, 240, 240, 250));

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

    public UIListener getListener() {
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

    @Override
    protected void paintComponent(Graphics g) {

        super.paintComponent(g);

        darkMode = api.userInterface().currentTheme() == Theme.DARK;

        Color color = darkMode ? Color.WHITE : Color.BLACK;

        copyCodeIcon.setIconColor(color);
        copySecretIcon.setIconColor(color);
        copySuccessIcon.setIconColor(color);
        removeIcon.setIconColor(color);

        setRegexValid(regexValid);

    }

    private void createCodeDisplay() {

        this.nameLbl = new JLabel("XXXXXXXXXXXXXXXXXXXX");
        nameLbl.setPreferredSize(nameLbl.getPreferredSize());
        nameLbl.setText(code.getName());
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
        nameLblCons.anchor = GridBagConstraints.WEST;

        this.algoIcon = FontIcon.of(MaterialDesignS.SHIELD_KEY);

        Color algoColor = new Color(100, 100, 100);

        this.algoLbl = new JLabel(formatCrypto(code.getCrypto()));
        algoLbl.setFont(font.deriveFont(Font.BOLD));
        algoLbl.setForeground(algoColor);
        algoLbl.addMouseListener(this);
        algoLbl.setToolTipText("Hashing algorithm");
        algoLbl.setHorizontalAlignment(JLabel.RIGHT);

        algoLbl.setIcon(algoIcon);

        algoIcon.setIconColor(algoColor);
        algoIcon.setIconSize(font.getSize());

        int inset = insets.top;

        GridBagConstraints algoLblCons = new GridBagConstraints();
        algoLblCons.gridx = 3;
        algoLblCons.gridy = 0;
        algoLblCons.weightx = 0;
        algoLblCons.weighty = .5;
        algoLblCons.gridheight = 1;
        algoLblCons.gridwidth = 1;
        algoLblCons.insets = new Insets(inset, inset, inset, inset * 2);
        algoLblCons.fill = GridBagConstraints.BOTH;
        algoLblCons.anchor = GridBagConstraints.EAST;

        this.codeLbl = new JLabel("888 888");
        codeLbl.setFont(font.deriveFont(Font.BOLD, font.getSize() * 2f));
        codeLbl.setPreferredSize(codeLbl.getPreferredSize());
        codeLbl.addMouseListener(this);
        codeLbl.setToolTipText(code.generateCode());
        codeLbl.setHorizontalAlignment(JLabel.CENTER);

        GridBagConstraints codeLblCons = new GridBagConstraints();
        codeLblCons.gridx = 0;
        codeLblCons.gridy = 1;
        codeLblCons.weightx = 0;
        codeLblCons.weighty = 0;
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
        progressBarCons.weightx = 0;
        progressBarCons.weighty = .5;
        progressBarCons.gridheight = 1;
        progressBarCons.gridwidth = 1;
        progressBarCons.insets = insets;
        progressBarCons.fill = GridBagConstraints.BOTH;
        progressBarCons.anchor = GridBagConstraints.CENTER;

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

        this.add(matchLbl, matchLblCons);

        this.matchField = new JTextField("XXXXXXXXXXXXXXXXXXXX");
        matchField.setPreferredSize(matchField.getSize());
        matchField.setText(code.getMatch());
        matchField.setFont(font);
        matchField.addMouseListener(this);
        matchField.addKeyListener(this);
        matchField.setEnabled(code.isEnabled());

        boolean darkMode = api.userInterface().currentTheme() == Theme.DARK;

        Color matchFieldBorderColor = darkMode ? new Color(0, 0, 0, 0) : Color.LIGHT_GRAY;

        Border matchFieldLineBorder = BorderFactory.createLineBorder(matchFieldBorderColor, 1);
        Border matchFieldMarginBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);

        matchField.setBorder(new CompoundBorder(matchFieldLineBorder, matchFieldMarginBorder));

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

        this.add(matchField, matchFieldCons);

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

            listener.setCodeEnabled(code, enabled);
            matchField.setEnabled(enabled);
            matchLbl.setEnabled(enabled);

        });

        this.add(enabledBox, enabledBoxCons);

    }

    private void createButtons() {

        this.copySuccessIcon = FontIcon.of(MaterialDesignC.CLIPBOARD_CHECK);
        copySuccessIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);
        copySuccessIcon.setIconSize(font.getSize());

        this.copyCodeIcon = FontIcon.of(MaterialDesignS.SHIELD_LOCK);
        copyCodeIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);
        copyCodeIcon.setIconSize(font.getSize());

        this.copyCodeBtn = new JButton();
        copyCodeBtn.setIcon(copyCodeIcon);
        copyCodeBtn.setFont(font);
        copyCodeBtn.addMouseListener(this);
        copyCodeBtn.setToolTipText("Copy code to clipboard");

        GridBagConstraints copyCodeBtnCons = new GridBagConstraints();
        copyCodeBtnCons.gridx = 2;
        copyCodeBtnCons.gridy = 1;
        copyCodeBtnCons.weightx = .20;
        copyCodeBtnCons.weighty = .5;
        copyCodeBtnCons.gridheight = 1;
        copyCodeBtnCons.gridwidth = 1;
        copyCodeBtnCons.ipadx = 0;
        copyCodeBtnCons.ipady = 10;
        copyCodeBtnCons.insets = insets;
        copyCodeBtnCons.fill = GridBagConstraints.BOTH;
        copyCodeBtnCons.anchor = GridBagConstraints.CENTER;

        Timer copyCodeDelay = new Timer(200, m -> {

            copyCodeBtn.setIcon(copyCodeIcon);

        });

        copyCodeDelay.setRepeats(false);

        copyCodeBtn.addActionListener(l -> {

            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(code.generateCode()), null);

            copyCodeBtn.setIcon(copySuccessIcon);

            // TODO: Remove
            logOutput(matchField.getLocationOnScreen() + "", true);

            copyCodeDelay.restart();

        });

        this.add(copyCodeBtn, copyCodeBtnCons);

        this.copySecretIcon = FontIcon.of(MaterialDesignK.KEY);
        copySecretIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);
        copySecretIcon.setIconSize(font.getSize());

        this.copySecretBtn = new JButton();
        copySecretBtn.setIcon(copySecretIcon);
        copySecretBtn.setFont(font);
        copySecretBtn.addMouseListener(this);
        copySecretBtn.setToolTipText("Copy secret to clipboard");

        GridBagConstraints copySecretBtnCons = new GridBagConstraints();
        copySecretBtnCons.gridx = 3;
        copySecretBtnCons.gridy = 1;
        copySecretBtnCons.weightx = .1;
        copySecretBtnCons.weighty = .5;
        copySecretBtnCons.gridheight = 1;
        copySecretBtnCons.gridwidth = 1;
        copySecretBtnCons.ipadx = 0;
        copySecretBtnCons.ipady = 10;
        copySecretBtnCons.insets = insets;
        copySecretBtnCons.fill = GridBagConstraints.BOTH;
        copySecretBtnCons.anchor = GridBagConstraints.CENTER;

        Timer copySecretDelay = new Timer(200, m -> {

            copySecretBtn.setIcon(copySecretIcon);

        });

        copySecretDelay.setRepeats(false);

        copySecretBtn.addActionListener(l -> {

            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(code.getUri()), null);

            copySecretBtn.setIcon(copySuccessIcon);

            copySecretDelay.restart();

        });

        this.add(copySecretBtn, copySecretBtnCons);

        this.removeBtn = new JButton();
        removeBtn.setFont(font);
        removeBtn.addMouseListener(this);

        this.removeIcon = FontIcon.of(MaterialDesignC.CLOSE);
        removeIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);
        removeIcon.setIconSize(font.getSize());

        removeBtn.setIcon(removeIcon);

        GridBagConstraints removeBtnCons = new GridBagConstraints();
        removeBtnCons.gridx = 2;
        removeBtnCons.gridy = 2;
        removeBtnCons.weightx = 0;
        removeBtnCons.weighty = .5;
        removeBtnCons.gridheight = 1;
        removeBtnCons.gridwidth = 2;
        removeBtnCons.insets = insets;
        removeBtnCons.ipadx = 0;
        removeBtnCons.ipady = 0;
        removeBtnCons.fill = GridBagConstraints.BOTH;
        removeBtnCons.anchor = GridBagConstraints.CENTER;

        removeBtn.addActionListener(l -> {

            int res = JOptionPane.showConfirmDialog(SwingUtilities.getWindowAncestor(this),
                    "Are you sure you want to remove " + code.getName() + "? This cannot be undone.",
                    "Remove Code Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

            if (res == JOptionPane.OK_OPTION)
                listener.removeCodeItem(this);

        });

        this.add(removeBtn, removeBtnCons);

    }

    private void updateProgressBar() {

        int duration = code.getDuration();
        int progress = duration - (((int) (System.currentTimeMillis() / 1000)) % duration);

        progressBar.setValue(progress);

    }

}
