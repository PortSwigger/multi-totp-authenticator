package com.stephensantilli.totp.ui;

import static com.stephensantilli.totp.TOTP.DEFAULT_DIGITS;
import static com.stephensantilli.totp.TOTP.DEFAULT_DURATION;
import static com.stephensantilli.totp.TOTP.api;

import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

import com.stephensantilli.totp.Code;
import com.stephensantilli.totp.CodeListener;
import com.stephensantilli.totp.TOTP;

public class Entry extends JPanel {

    private JLabel secretLbl, digitsLbl, nameLbl, durationLbl, algoLbl;

    private JTextField secretField, digitsField, durationField, nameField;

    private ButtonGroup algoBtns;

    private JRadioButton sha1Rad, sha256Rad, sha512Rad;

    private JButton addBtn;

    public Entry(CodeListener listener) {

        GridBagLayout layout = new GridBagLayout();

        setLayout(layout);

        Font font = api.userInterface().currentDisplayFont();

        Insets insets = new Insets(5, 5, 5, 5);

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

        this.algoBtns = new ButtonGroup();
        algoBtns.add(sha1Rad);
        algoBtns.add(sha256Rad);
        algoBtns.add(sha512Rad);

        this.addBtn = new JButton("Add");
        addBtn.setFont(font.deriveFont(Font.BOLD, font.getSize() * 2));

        addBtn.setBackground(new Color(255, 102, 51));
        addBtn.setForeground(Color.WHITE);

        addBtn.addActionListener(l -> {

            try {

                listener.addCode(getCodeFromEntry(), true);

            } catch (Exception e) {

                JOptionPane.showMessageDialog(
                        api.userInterface().swingUtils().suiteFrame(),
                        "Failed to add code: " + e.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);

            }

        });

        GridBagConstraints addBtnCons = new GridBagConstraints();
        addBtnCons.gridx = 8;
        addBtnCons.gridy = 0;
        addBtnCons.weightx = .5;
        addBtnCons.weighty = .5;
        addBtnCons.gridheight = 2;
        addBtnCons.gridwidth = 1;
        addBtnCons.insets = insets;
        addBtnCons.fill = GridBagConstraints.BOTH;
        addBtnCons.anchor = GridBagConstraints.EAST;

        this.add(addBtn, addBtnCons);

    }

    public String getCrypto() {

        ButtonModel bm = algoBtns.getSelection();

        if (bm.equals(sha256Rad.getModel()))
            return "HmacSHA256";
        if (bm.equals(sha512Rad.getModel()))
            return "HmacSHA512";
        else
            return "HmacSHA1";

    }

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

}