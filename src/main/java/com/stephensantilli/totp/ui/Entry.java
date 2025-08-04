package com.stephensantilli.totp.ui;

import static com.stephensantilli.totp.TOTP.DEFAULT_DIGITS;
import static com.stephensantilli.totp.TOTP.DEFAULT_DURATION;
import static com.stephensantilli.totp.TOTP.api;
import static com.stephensantilli.totp.TOTP.logOutput;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.kordamp.ikonli.materialdesign2.MaterialDesignC;
import org.kordamp.ikonli.materialdesign2.MaterialDesignP;
import org.kordamp.ikonli.materialdesign2.MaterialDesignQ;
import org.kordamp.ikonli.materialdesign2.MaterialDesignT;
import org.kordamp.ikonli.swing.FontIcon;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.stephensantilli.totp.Code;
import com.stephensantilli.totp.UIListener;

import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;

import com.stephensantilli.totp.TOTP;

/**
 * The UI element where users enter the details of a TOTP to add to their
 * project.
 */
public class Entry extends JPanel {

    private JLabel secretLbl, digitsLbl, nameLbl, durationLbl, algoLbl;

    private JTextField secretField, digitsField, durationField, nameField;

    private ButtonGroup algoBtns;

    private JRadioButton sha1Rad, sha256Rad, sha512Rad;

    private JButton addBtn, scanBtn, pasteBtn, scopeBtn;

    private FontIcon addIcon, scanIcon, pasteIcon, scopeIcon;

    private boolean darkMode;

    private Font font;

    private Insets insets;

    private UIListener listener;

    public Entry(UIListener listener) {

        GridBagLayout layout = new GridBagLayout();

        setLayout(layout);

        this.listener = listener;

        UserInterface ui = api.userInterface();

        this.font = ui.currentDisplayFont();
        this.darkMode = ui.currentTheme() == Theme.DARK;

        this.insets = new Insets(5, 5, 5, 5);

        createFields();
        createAlgoSelection();
        createButtons();

    }

    private void createAlgoSelection() {

        this.algoLbl = new JLabel("Algorithm:");
        algoLbl.setFont(font);

        GridBagConstraints algoLblCons = new GridBagConstraints();
        algoLblCons.gridx = 4;
        algoLblCons.gridy = 1;
        algoLblCons.weightx = 0;
        algoLblCons.weighty = .5;
        algoLblCons.gridheight = 1;
        algoLblCons.gridwidth = 1;
        algoLblCons.insets = insets;
        algoLblCons.anchor = GridBagConstraints.EAST;

        this.add(algoLbl, algoLblCons);

        this.sha1Rad = new JRadioButton("SHA-1");
        sha1Rad.setSelected(true);
        sha1Rad.setFont(font);

        GridBagConstraints sha1RadCons = new GridBagConstraints();
        sha1RadCons.gridx = 5;
        sha1RadCons.gridy = 1;
        sha1RadCons.weightx = .5;
        sha1RadCons.weighty = .5;
        sha1RadCons.gridheight = 1;
        sha1RadCons.gridwidth = 1;
        sha1RadCons.insets = insets;
        sha1RadCons.fill = GridBagConstraints.BOTH;
        sha1RadCons.anchor = GridBagConstraints.CENTER;

        this.add(sha1Rad, sha1RadCons);

        this.sha256Rad = new JRadioButton("SHA-256");
        sha256Rad.setFont(font);

        GridBagConstraints sha256RadCons = new GridBagConstraints();
        sha256RadCons.gridx = 6;
        sha256RadCons.gridy = 1;
        sha256RadCons.weightx = .5;
        sha256RadCons.weighty = .5;
        sha256RadCons.gridheight = 1;
        sha256RadCons.gridwidth = 1;
        sha256RadCons.insets = insets;
        sha256RadCons.fill = GridBagConstraints.BOTH;
        sha256RadCons.anchor = GridBagConstraints.CENTER;

        this.add(sha256Rad, sha256RadCons);

        this.sha512Rad = new JRadioButton("SHA-512");
        sha512Rad.setFont(font);

        GridBagConstraints sha512RadCons = new GridBagConstraints();
        sha512RadCons.gridx = 7;
        sha512RadCons.gridy = 1;
        sha512RadCons.weightx = .5;
        sha512RadCons.weighty = .5;
        sha512RadCons.gridheight = 1;
        sha512RadCons.gridwidth = 1;
        sha512RadCons.insets = insets;
        sha512RadCons.fill = GridBagConstraints.BOTH;
        sha512RadCons.anchor = GridBagConstraints.CENTER;

        this.add(sha512Rad, sha512RadCons);

    }

    private void createFields() {

        // Name Label
        this.nameLbl = new JLabel("Name:");
        nameLbl.setFont(font);

        GridBagConstraints nameLblCons = new GridBagConstraints();
        nameLblCons.gridx = 0;
        nameLblCons.gridy = 0;
        nameLblCons.weightx = 0;
        nameLblCons.weighty = .5;
        nameLblCons.gridheight = 1;
        nameLblCons.gridwidth = 1;
        nameLblCons.insets = insets;
        nameLblCons.anchor = GridBagConstraints.EAST;

        this.add(nameLbl, nameLblCons);

        // Name field
        this.nameField = new JTextField();
        nameField.setText("Name");

        GridBagConstraints nameFieldCons = new GridBagConstraints();
        nameFieldCons.gridx = 1;
        nameFieldCons.gridy = 0;
        nameFieldCons.weightx = .7;
        nameFieldCons.weighty = .5;
        nameFieldCons.gridheight = 1;
        nameFieldCons.gridwidth = 3;
        nameFieldCons.insets = insets;
        nameFieldCons.fill = GridBagConstraints.BOTH;
        nameFieldCons.anchor = GridBagConstraints.CENTER;

        this.add(nameField, nameFieldCons);

        // Secret label
        this.secretLbl = new JLabel("Secret:");
        secretLbl.setFont(font);

        GridBagConstraints secretLblCons = new GridBagConstraints();
        secretLblCons.gridx = 4;
        secretLblCons.gridy = 0;
        secretLblCons.weightx = 0;
        secretLblCons.weighty = .5;
        secretLblCons.gridheight = 1;
        secretLblCons.gridwidth = 1;
        secretLblCons.insets = insets;
        secretLblCons.fill = GridBagConstraints.VERTICAL;
        secretLblCons.anchor = GridBagConstraints.EAST;

        this.add(secretLbl, secretLblCons);

        this.secretField = new JTextField();
        secretField.setFont(font);

        GridBagConstraints secretFieldCons = new GridBagConstraints();
        secretFieldCons.gridx = 5;
        secretFieldCons.gridy = 0;
        secretFieldCons.weightx = .7;
        secretFieldCons.weighty = .5;
        secretFieldCons.gridheight = 1;
        secretFieldCons.gridwidth = 3;
        secretFieldCons.insets = insets;
        secretFieldCons.fill = GridBagConstraints.BOTH;
        secretFieldCons.anchor = GridBagConstraints.CENTER;

        this.add(secretField, secretFieldCons);

        // Duration Label
        this.durationLbl = new JLabel("Duration:");
        durationLbl.setFont(font);

        GridBagConstraints durationLblCons = new GridBagConstraints();
        durationLblCons.gridx = 0;
        durationLblCons.gridy = 1;
        durationLblCons.weightx = 0;
        durationLblCons.weighty = .5;
        durationLblCons.gridheight = 1;
        durationLblCons.gridwidth = 1;
        durationLblCons.insets = insets;
        durationLblCons.anchor = GridBagConstraints.EAST;

        this.add(durationLbl, durationLblCons);

        // Duration field
        this.durationField = new JTextField();
        durationField.setText(TOTP.DEFAULT_DURATION + "");
        durationField.setFont(font);

        GridBagConstraints durationFieldCons = new GridBagConstraints();
        durationFieldCons.gridx = 1;
        durationFieldCons.gridy = 1;
        durationFieldCons.weightx = .7;
        durationFieldCons.weighty = .5;
        durationFieldCons.gridheight = 1;
        durationFieldCons.gridwidth = 1;
        durationFieldCons.insets = insets;
        durationFieldCons.fill = GridBagConstraints.BOTH;
        durationFieldCons.anchor = GridBagConstraints.CENTER;

        this.add(durationField, durationFieldCons);

        this.digitsLbl = new JLabel("Code Length:");
        digitsLbl.setFont(font);

        GridBagConstraints digitsLblCons = new GridBagConstraints();
        digitsLblCons.gridx = 2;
        digitsLblCons.gridy = 1;
        digitsLblCons.weightx = 0;
        digitsLblCons.weighty = .5;
        digitsLblCons.gridheight = 1;
        digitsLblCons.gridwidth = 1;
        digitsLblCons.insets = insets;
        digitsLblCons.anchor = GridBagConstraints.EAST;

        this.add(digitsLbl, digitsLblCons);

        this.digitsField = new JTextField();
        digitsField.setText(DEFAULT_DIGITS + "");
        digitsField.setFont(font);

        GridBagConstraints digitsFieldCons = new GridBagConstraints();
        digitsFieldCons.gridx = 3;
        digitsFieldCons.gridy = 1;
        digitsFieldCons.weightx = .7;
        digitsFieldCons.weighty = .5;
        digitsFieldCons.gridheight = 1;
        digitsFieldCons.gridwidth = 1;
        digitsFieldCons.insets = insets;
        digitsFieldCons.fill = GridBagConstraints.BOTH;
        digitsFieldCons.anchor = GridBagConstraints.CENTER;

        this.add(digitsField, digitsFieldCons);

    }

    private void createButtons() {

        this.algoBtns = new ButtonGroup();
        algoBtns.add(sha1Rad);
        algoBtns.add(sha256Rad);
        algoBtns.add(sha512Rad);

        Font btnFont = font.deriveFont(Font.BOLD, font.getSize() * 1.25f);

        this.scanBtn = new JButton("Scan QR");
        scanBtn.setFont(btnFont);

        this.scanIcon = FontIcon.of(MaterialDesignQ.QRCODE_SCAN);
        scanIcon.setIconSize(btnFont.getSize());
        scanIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);

        scanBtn.setIcon(scanIcon);
        scanBtn.setIconTextGap(10);
        scanBtn.setHorizontalTextPosition(JButton.RIGHT);
        scanBtn.setHorizontalAlignment(JButton.LEFT);

        scanBtn.addActionListener(l -> {

            try {

                String scanResult = scanQR();
                logOutput("Scanned QR code! Got: " + scanResult, false);

                setEntryFromURI(scanResult);

            } catch (NotFoundException e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        "No QR code found.",
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

            } catch (Exception e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        e.getMessage(),
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

            }

        });

        GridBagConstraints scanBtnCons = new GridBagConstraints();
        scanBtnCons.gridx = 8;
        scanBtnCons.gridy = 0;
        scanBtnCons.weightx = 0;
        scanBtnCons.weighty = .5;
        scanBtnCons.gridheight = 1;
        scanBtnCons.gridwidth = 1;
        scanBtnCons.insets = insets;
        scanBtnCons.fill = GridBagConstraints.BOTH;
        scanBtnCons.anchor = GridBagConstraints.EAST;

        this.add(scanBtn, scanBtnCons);

        this.pasteBtn = new JButton("Paste QR");
        pasteBtn.setFont(btnFont);

        this.pasteIcon = FontIcon.of(MaterialDesignC.CLIPBOARD_PLUS_OUTLINE);
        pasteIcon.setIconSize(btnFont.getSize());
        pasteIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);

        pasteBtn.setIcon(pasteIcon);
        pasteBtn.setIconTextGap(10);
        pasteBtn.setHorizontalTextPosition(JButton.RIGHT);
        pasteBtn.setHorizontalAlignment(JButton.LEFT);

        pasteBtn.addActionListener(l -> {

            try {

                String scanResult = pasteQR();
                logOutput("Pasted QR code! Got: " + scanResult, false);

                setEntryFromURI(scanResult);

            } catch (NotFoundException e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        "No QR code found.",
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

            } catch (Exception e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        e.getMessage(),
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

            }

        });

        GridBagConstraints pasteBtnCons = new GridBagConstraints();
        pasteBtnCons.gridx = 8;
        pasteBtnCons.gridy = 1;
        pasteBtnCons.weightx = 0;
        pasteBtnCons.weighty = .5;
        pasteBtnCons.gridheight = 1;
        pasteBtnCons.gridwidth = 1;
        pasteBtnCons.insets = insets;
        pasteBtnCons.fill = GridBagConstraints.BOTH;
        pasteBtnCons.anchor = GridBagConstraints.EAST;

        this.add(pasteBtn, pasteBtnCons);

        this.scopeBtn = new JButton("Scope");
        scopeBtn.setFont(btnFont);

        this.scopeIcon = FontIcon.of(MaterialDesignT.TELESCOPE);
        scopeIcon.setIconSize(btnFont.getSize());
        scopeIcon.setIconColor(darkMode ? Color.WHITE : Color.BLACK);

        scopeBtn.setIcon(scopeIcon);
        scopeBtn.setIconTextGap(10);
        scopeBtn.setHorizontalTextPosition(JButton.RIGHT);
        scopeBtn.setHorizontalAlignment(JButton.LEFT);

        scopeBtn.addActionListener(l -> {

            try {

                listener.openScopeDialog();

            } catch (Exception e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        e.getMessage(),
                        "Error",
                        JOptionPane.WARNING_MESSAGE);
                e.printStackTrace();
            }

        });

        GridBagConstraints scopeBtnCons = new GridBagConstraints();
        scopeBtnCons.gridx = 9;
        scopeBtnCons.gridy = 0;
        scopeBtnCons.weightx = 0;
        scopeBtnCons.weighty = .5;
        scopeBtnCons.gridheight = 1;
        scopeBtnCons.gridwidth = 1;
        scopeBtnCons.insets = insets;
        scopeBtnCons.fill = GridBagConstraints.BOTH;
        scopeBtnCons.anchor = GridBagConstraints.EAST;

        this.add(scopeBtn, scopeBtnCons);

        this.addBtn = new JButton("Add");
        addBtn.setFont(btnFont);
        addBtn.setBackground(new Color(255, 102, 51));
        addBtn.setForeground(Color.WHITE);

        this.addIcon = FontIcon.of(MaterialDesignP.PLUS_CIRCLE_OUTLINE);
        addIcon.setIconSize(btnFont.getSize());
        addIcon.setIconColor(Color.WHITE);

        addBtn.setIcon(addIcon);
        addBtn.setIconTextGap(10);
        addBtn.setHorizontalTextPosition(JButton.RIGHT);
        addBtn.setHorizontalAlignment(JButton.LEFT);

        addBtn.addActionListener(l -> {

            try {

                listener.addCode(getCodeFromEntry(), true);

            } catch (Exception e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        e.getMessage(),
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

                e.printStackTrace();

            }

        });

        GridBagConstraints addBtnCons = new GridBagConstraints();
        addBtnCons.gridx = 9;
        addBtnCons.gridy = 1;
        addBtnCons.weightx = 0;
        addBtnCons.weighty = .5;
        addBtnCons.gridheight = 1;
        addBtnCons.gridwidth = 1;
        addBtnCons.insets = insets;
        addBtnCons.fill = GridBagConstraints.BOTH;
        addBtnCons.anchor = GridBagConstraints.EAST;

        this.add(addBtn, addBtnCons);

    }

    /**
     * Creates a TOTP code from the user-supplied data in the fields of this form.
     * 
     * @return A {@link Code} object
     * @throws Exception If the user-entered data is invalid.
     */
    public Code getCodeFromEntry() throws Exception {

        String name = nameField.getText();
        String secret = secretField.getText();

        int digits = DEFAULT_DIGITS;
        try {
            digits = Integer.parseInt(this.digitsField.getText());
        } catch (Exception e) {
            throw new Exception("Unable to parse length of code entered!");
        }

        int duration = DEFAULT_DURATION;
        try {
            duration = Integer.parseInt(this.durationField.getText());
        } catch (Exception e) {
            throw new Exception("Unable to parse the duration!");
        }

        return new Code(name, secret, "_" + name + "_", digits, duration, getCrypto(), true);

    }

    public void resetEntry() {

        this.secretField.setText("");
        this.nameField.setText("Name");

        this.digitsField.setText(DEFAULT_DIGITS + "");
        this.durationField.setText(DEFAULT_DURATION + "");

        algoBtns.setSelected(sha1Rad.getModel(), true);

    }

    @Override
    protected void paintComponent(Graphics g) {

        super.paintComponent(g);

        darkMode = api.userInterface().currentTheme() == Theme.DARK;

        Color color = darkMode ? Color.WHITE : Color.BLACK;

        scanIcon.setIconColor(color);
        pasteIcon.setIconColor(color);
        scopeIcon.setIconColor(color);

    }

    private String getCrypto() {

        ButtonModel bm = algoBtns.getSelection();

        if (bm.equals(sha256Rad.getModel()))
            return "HmacSHA256";
        if (bm.equals(sha512Rad.getModel()))
            return "HmacSHA512";
        else
            return "HmacSHA1";

    }

    private void setEntryFromURI(String uri) throws Exception {

        Pattern pattern = Pattern.compile(
                "otpauth://(?<type>totp|hotp)/(?<label>[^?]+)\\?(?<params>(&?issuer=(?<issuer>[^&]+))|(&?secret=(?<secret>[^&]+))|(&?digits=(?<digits>[^&]+))|(&?period=(?<period>[^&]+))|(&?algorithm=(?<algorithm>[^&]+)))+");

        uri = api.utilities().urlUtils().decode(uri);

        Matcher matcher = pattern.matcher(uri);

        if (!matcher.matches())
            throw new Exception("Invalid or malformed TOTP URI!");

        String uriType = matcher.group("type"),
                uriLabel = matcher.group("label"),
                uriIssuer = matcher.group("issuer"),
                uriSecret = matcher.group("secret"),
                uriDigits = matcher.group("digits"),
                uriPeriod = matcher.group("period"),
                uriAlgorithm = matcher.group("algorithm");

        if (uriType == null || !uriType.equals("totp"))
            throw new Exception("Invalid URI type. Must be \"totp\".");

        if (uriSecret == null || uriSecret.equals(""))
            throw new Exception("Invalid URI secret.");

        secretField.setText(uriSecret);

        if (uriLabel != null)
            nameField.setText(uriLabel);

        if (uriIssuer != null)
            nameField.setText(nameField.getText() + " - " + uriIssuer);

        if (uriDigits != null && !uriDigits.equals(""))
            digitsField.setText(uriDigits);

        if (uriPeriod != null && !uriPeriod.equals(""))
            durationField.setText(uriPeriod);

        if (uriAlgorithm != null) {

            switch (uriAlgorithm) {
                case "SHA256":
                    algoBtns.setSelected(sha256Rad.getModel(), true);
                    break;
                case "SHA512":
                    algoBtns.setSelected(sha512Rad.getModel(), true);
                    break;
                default:
                    algoBtns.setSelected(sha1Rad.getModel(), true);

            }

        }

    }

    private String scanQR() throws Exception, NotFoundException {

        Robot robot = new Robot();
        Rectangle screenRect = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
        BufferedImage screenshot = robot.createScreenCapture(screenRect);

        return decodeQR(screenshot);

    }

    private String pasteQR() throws Exception, NotFoundException {

        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

        Object data;

        try {
            data = clipboard.getContents(this).getTransferData(DataFlavor.imageFlavor);
        } catch (IOException e) {
            throw new Exception("Unable to get TOTP from clipboard due to an IO Exception.");
        } catch (UnsupportedFlavorException e) {

            try {

                data = clipboard.getContents(this).getTransferData(DataFlavor.stringFlavor);

                if (data instanceof String)
                    return (String) data;
                else
                    throw new Exception("Invalid data type on clipboard.");

            } catch (IOException | UnsupportedFlavorException ex) {
                throw new Exception("No QR image or URI on clipboard.");
            }

        }

        if (!(data instanceof Image))
            throw new Exception("Pasted contents are not an image!");

        Image screenshot = (Image) data;

        BufferedImage image = new BufferedImage(screenshot.getWidth(null), screenshot.getHeight(null),
                BufferedImage.TYPE_INT_ARGB);

        Graphics2D graphics = image.createGraphics();
        graphics.drawImage(screenshot, 0, 0, null);
        graphics.dispose();

        return decodeQR(image);

    }

    private String decodeQR(BufferedImage image) throws NotFoundException {

        int width = image.getWidth(null), height = image.getHeight(null);

        RGBLuminanceSource luminanace = new RGBLuminanceSource(width,
                height,
                image.getRGB(0,
                        0,
                        width,
                        height,
                        null,
                        0,
                        width));

        HybridBinarizer binarizer = new HybridBinarizer(luminanace);
        BinaryBitmap bitmap = new BinaryBitmap(binarizer);

        MultiFormatReader reader = new MultiFormatReader();

        return reader.decode(bitmap, Map.of(DecodeHintType.POSSIBLE_FORMATS, List.of(BarcodeFormat.QR_CODE))).getText();

    }

}