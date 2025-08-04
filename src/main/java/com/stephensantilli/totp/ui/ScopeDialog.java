package com.stephensantilli.totp.ui;

import static com.stephensantilli.totp.TOTP.logError;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import com.stephensantilli.totp.UIListener;
import com.stephensantilli.totp.ScopeItem;
import com.stephensantilli.totp.ScopeOption;
import burp.api.montoya.core.ToolType;

/**
 * The dialog a user uses to configure the scope of requests the extension will
 * listen to.
 */
public class ScopeDialog extends JPanel implements TableModelListener, ItemListener {

    private UIListener listener;

    private JLabel noteLbl, prefixLbl, toolsScopeLbl, urlScopeLbl;

    private JTextField prefixField;

    private JButton addBtn, removeBtn, okBtn;

    private JCheckBox targetBox, scannerBox, repeaterBox, intruderBox, sequencerBox, aiBox, extensionBox, proxyBox,
            includeSubdomainsBox;

    private JRadioButton allScopeRad, suiteScopeRad, customScopeRad;

    private ButtonGroup prefixRadBtns;

    private JTable table;

    private JScrollPane tableScrollPane;

    private DefaultTableModel model;

    public ScopeDialog(UIListener listener) {

        this.listener = listener;

        setLayout(new GridBagLayout());

        int inset = 10;
        Insets insets = new Insets(inset, inset, inset, inset);

        this.noteLbl = new JLabel("Note: The scope you apply here does not impact session handling rules.");
        noteLbl.setFont(noteLbl.getFont().deriveFont(Font.ITALIC));

        GridBagConstraints noteLblCons = new GridBagConstraints();
        noteLblCons.gridx = 0;
        noteLblCons.gridy = 0;
        noteLblCons.weightx = .5;
        noteLblCons.weighty = .5;
        noteLblCons.gridheight = 1;
        noteLblCons.gridwidth = 8;
        noteLblCons.insets = insets;
        noteLblCons.ipadx = 0;
        noteLblCons.ipady = 0;
        noteLblCons.fill = GridBagConstraints.BOTH;
        noteLblCons.anchor = GridBagConstraints.CENTER;

        this.add(noteLbl, noteLblCons);

        this.toolsScopeLbl = new JLabel("Tools scope");
        toolsScopeLbl.setFont(toolsScopeLbl.getFont().deriveFont(Font.BOLD));

        GridBagConstraints toolsLblCons = new GridBagConstraints();
        toolsLblCons.gridx = 0;
        toolsLblCons.gridy = 1;
        toolsLblCons.weightx = .5;
        toolsLblCons.weighty = .5;
        toolsLblCons.gridheight = 1;
        toolsLblCons.gridwidth = 8;
        toolsLblCons.insets = insets;
        toolsLblCons.ipadx = 0;
        toolsLblCons.ipady = 0;
        toolsLblCons.fill = GridBagConstraints.BOTH;
        toolsLblCons.anchor = GridBagConstraints.CENTER;

        this.add(toolsScopeLbl, toolsLblCons);

        this.targetBox = new JCheckBox("Target");

        targetBox.addItemListener(this);

        GridBagConstraints targetBoxCons = new GridBagConstraints();
        targetBoxCons.gridx = 0;
        targetBoxCons.gridy = 4;
        targetBoxCons.weightx = .5;
        targetBoxCons.weighty = .5;
        targetBoxCons.gridheight = 1;
        targetBoxCons.gridwidth = 2;
        targetBoxCons.insets = insets;
        targetBoxCons.ipadx = 0;
        targetBoxCons.ipady = 0;
        targetBoxCons.fill = GridBagConstraints.BOTH;
        targetBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(targetBox, targetBoxCons);

        this.scannerBox = new JCheckBox("Scanner");

        scannerBox.addItemListener(this);

        GridBagConstraints scannerBoxCons = new GridBagConstraints();
        scannerBoxCons.gridx = 2;
        scannerBoxCons.gridy = 4;
        scannerBoxCons.weightx = .5;
        scannerBoxCons.weighty = .5;
        scannerBoxCons.gridheight = 1;
        scannerBoxCons.gridwidth = 2;
        scannerBoxCons.insets = insets;
        scannerBoxCons.ipadx = 0;
        scannerBoxCons.ipady = 0;
        scannerBoxCons.fill = GridBagConstraints.BOTH;
        scannerBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(scannerBox, scannerBoxCons);

        this.repeaterBox = new JCheckBox("Repeater");

        repeaterBox.addItemListener(this);

        GridBagConstraints repeaterBoxCons = new GridBagConstraints();
        repeaterBoxCons.gridx = 4;
        repeaterBoxCons.gridy = 4;
        repeaterBoxCons.weightx = .5;
        repeaterBoxCons.weighty = .5;
        repeaterBoxCons.gridheight = 1;
        repeaterBoxCons.gridwidth = 2;
        repeaterBoxCons.insets = insets;
        repeaterBoxCons.ipadx = 0;
        repeaterBoxCons.ipady = 0;
        repeaterBoxCons.fill = GridBagConstraints.BOTH;
        repeaterBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(repeaterBox, repeaterBoxCons);

        this.intruderBox = new JCheckBox("Intruder");

        intruderBox.addItemListener(this);

        GridBagConstraints intruderBoxCons = new GridBagConstraints();
        intruderBoxCons.gridx = 6;
        intruderBoxCons.gridy = 4;
        intruderBoxCons.weightx = .5;
        intruderBoxCons.weighty = .5;
        intruderBoxCons.gridheight = 1;
        intruderBoxCons.gridwidth = 2;
        intruderBoxCons.insets = insets;
        intruderBoxCons.ipadx = 0;
        intruderBoxCons.ipady = 0;
        intruderBoxCons.fill = GridBagConstraints.BOTH;
        intruderBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(intruderBox, intruderBoxCons);

        this.sequencerBox = new JCheckBox("Sequencer");

        sequencerBox.addItemListener(this);

        GridBagConstraints sequencerBoxCons = new GridBagConstraints();
        sequencerBoxCons.gridx = 0;
        sequencerBoxCons.gridy = 5;
        sequencerBoxCons.weightx = .5;
        sequencerBoxCons.weighty = .5;
        sequencerBoxCons.gridheight = 1;
        sequencerBoxCons.gridwidth = 2;
        sequencerBoxCons.insets = insets;
        sequencerBoxCons.ipadx = 0;
        sequencerBoxCons.ipady = 0;
        sequencerBoxCons.fill = GridBagConstraints.BOTH;
        sequencerBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(sequencerBox, sequencerBoxCons);

        this.aiBox = new JCheckBox("AI");

        aiBox.addItemListener(this);

        GridBagConstraints aiBoxCons = new GridBagConstraints();
        aiBoxCons.gridx = 2;
        aiBoxCons.gridy = 5;
        aiBoxCons.weightx = .5;
        aiBoxCons.weighty = .5;
        aiBoxCons.gridheight = 1;
        aiBoxCons.gridwidth = 2;
        aiBoxCons.insets = insets;
        aiBoxCons.ipadx = 0;
        aiBoxCons.ipady = 0;
        aiBoxCons.fill = GridBagConstraints.BOTH;
        aiBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(aiBox, aiBoxCons);

        this.extensionBox = new JCheckBox("Extensions");

        extensionBox.addItemListener(this);

        GridBagConstraints extensionBoxCons = new GridBagConstraints();
        extensionBoxCons.gridx = 4;
        extensionBoxCons.gridy = 5;
        extensionBoxCons.weightx = .5;
        extensionBoxCons.weighty = .5;
        extensionBoxCons.gridheight = 1;
        extensionBoxCons.gridwidth = 2;
        extensionBoxCons.insets = insets;
        extensionBoxCons.ipadx = 0;
        extensionBoxCons.ipady = 0;
        extensionBoxCons.fill = GridBagConstraints.BOTH;
        extensionBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(extensionBox, extensionBoxCons);

        this.proxyBox = new JCheckBox("Proxy (use with caution)");

        proxyBox.addItemListener(this);

        GridBagConstraints proxyBoxCons = new GridBagConstraints();
        proxyBoxCons.gridx = 6;
        proxyBoxCons.gridy = 5;
        proxyBoxCons.weightx = .5;
        proxyBoxCons.weighty = .5;
        proxyBoxCons.gridheight = 1;
        proxyBoxCons.gridwidth = 2;
        proxyBoxCons.insets = insets;
        proxyBoxCons.ipadx = 0;
        proxyBoxCons.ipady = 0;
        proxyBoxCons.fill = GridBagConstraints.BOTH;
        proxyBoxCons.anchor = GridBagConstraints.CENTER;

        this.add(proxyBox, proxyBoxCons);

        this.urlScopeLbl = new JLabel("URL Scope");
        urlScopeLbl.setFont(urlScopeLbl.getFont().deriveFont(Font.BOLD));

        GridBagConstraints prefixLblCons = new GridBagConstraints();
        prefixLblCons.gridx = 0;
        prefixLblCons.gridy = 6;
        prefixLblCons.weightx = .5;
        prefixLblCons.weighty = .5;
        prefixLblCons.gridheight = 1;
        prefixLblCons.gridwidth = 8;
        prefixLblCons.insets = insets;
        prefixLblCons.ipadx = 0;
        prefixLblCons.ipady = 0;
        prefixLblCons.fill = GridBagConstraints.BOTH;
        prefixLblCons.anchor = GridBagConstraints.CENTER;

        this.add(urlScopeLbl, prefixLblCons);

        this.allScopeRad = new JRadioButton("Include all URLs");

        allScopeRad.addItemListener(this);

        GridBagConstraints allScopeRadCons = new GridBagConstraints();
        allScopeRadCons.gridx = 0;
        allScopeRadCons.gridy = 7;
        allScopeRadCons.weightx = .5;
        allScopeRadCons.weighty = .5;
        allScopeRadCons.gridheight = 1;
        allScopeRadCons.gridwidth = 8;
        allScopeRadCons.insets = insets;
        allScopeRadCons.ipadx = 0;
        allScopeRadCons.ipady = 0;
        allScopeRadCons.fill = GridBagConstraints.BOTH;
        allScopeRadCons.anchor = GridBagConstraints.CENTER;

        this.add(allScopeRad, allScopeRadCons);

        this.suiteScopeRad = new JRadioButton("Use suite scope [defined in Target tab]");

        suiteScopeRad.addItemListener(this);

        GridBagConstraints suiteScopeRadCons = new GridBagConstraints();
        suiteScopeRadCons.gridx = 0;
        suiteScopeRadCons.gridy = 8;
        suiteScopeRadCons.weightx = .5;
        suiteScopeRadCons.weighty = .5;
        suiteScopeRadCons.gridheight = 1;
        suiteScopeRadCons.gridwidth = 8;
        suiteScopeRadCons.insets = insets;
        suiteScopeRadCons.ipadx = 0;
        suiteScopeRadCons.ipady = 0;
        suiteScopeRadCons.fill = GridBagConstraints.BOTH;
        suiteScopeRadCons.anchor = GridBagConstraints.CENTER;

        this.add(suiteScopeRad, suiteScopeRadCons);

        this.customScopeRad = new JRadioButton("Custom scope");

        customScopeRad.addItemListener(this);

        GridBagConstraints customScopeRadCons = new GridBagConstraints();
        customScopeRadCons.gridx = 0;
        customScopeRadCons.gridy = 9;
        customScopeRadCons.weightx = .5;
        customScopeRadCons.weighty = .5;
        customScopeRadCons.gridheight = 1;
        customScopeRadCons.gridwidth = 8;
        customScopeRadCons.insets = insets;
        customScopeRadCons.ipadx = 0;
        customScopeRadCons.ipady = 0;
        customScopeRadCons.fill = GridBagConstraints.BOTH;
        customScopeRadCons.anchor = GridBagConstraints.CENTER;

        this.add(customScopeRad, customScopeRadCons);

        this.prefixRadBtns = new ButtonGroup();
        prefixRadBtns.add(allScopeRad);
        prefixRadBtns.add(suiteScopeRad);
        prefixRadBtns.add(customScopeRad);

        this.prefixLbl = new JLabel("Prefix:");

        GridBagConstraints urlLblCons = new GridBagConstraints();
        urlLblCons.gridx = 0;
        urlLblCons.gridy = 10;
        urlLblCons.weightx = 0;
        urlLblCons.weighty = .5;
        urlLblCons.gridheight = 1;
        urlLblCons.gridwidth = 1;
        urlLblCons.insets = insets;
        urlLblCons.ipadx = 0;
        urlLblCons.ipady = 0;
        urlLblCons.fill = GridBagConstraints.BOTH;
        urlLblCons.anchor = GridBagConstraints.CENTER;

        this.add(prefixLbl, urlLblCons);

        this.prefixField = new JTextField();

        GridBagConstraints urlFieldCons = new GridBagConstraints();
        urlFieldCons.gridx = 1;
        urlFieldCons.gridy = 10;
        urlFieldCons.weightx = .75;
        urlFieldCons.weighty = .5;
        urlFieldCons.gridheight = 1;
        urlFieldCons.gridwidth = 5;
        urlFieldCons.insets = insets;
        urlFieldCons.ipadx = 0;
        urlFieldCons.ipady = 0;
        urlFieldCons.fill = GridBagConstraints.BOTH;
        urlFieldCons.anchor = GridBagConstraints.WEST;

        this.add(prefixField, urlFieldCons);

        this.includeSubdomainsBox = new JCheckBox("Include subdomains?");

        GridBagConstraints includeSubdomainsCons = new GridBagConstraints();
        includeSubdomainsCons.gridx = 6;
        includeSubdomainsCons.gridy = 10;
        includeSubdomainsCons.weightx = .5;
        includeSubdomainsCons.weighty = .5;
        includeSubdomainsCons.gridheight = 1;
        includeSubdomainsCons.gridwidth = 1;
        includeSubdomainsCons.insets = insets;
        includeSubdomainsCons.ipadx = 0;
        includeSubdomainsCons.ipady = 0;
        includeSubdomainsCons.fill = GridBagConstraints.BOTH;
        includeSubdomainsCons.anchor = GridBagConstraints.CENTER;

        this.add(includeSubdomainsBox, includeSubdomainsCons);

        this.addBtn = new JButton("Add");

        addBtn.addActionListener(l -> {

            try {

                listener.addScopeItem(new ScopeItem(prefixField.getText(), includeSubdomainsBox.isSelected(), true));

            } catch (Exception e) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        e.getMessage(),
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

            }

            clearInput();

        });

        GridBagConstraints addBtnCons = new GridBagConstraints();
        addBtnCons.gridx = 7;
        addBtnCons.gridy = 10;
        addBtnCons.weightx = .5;
        addBtnCons.weighty = .5;
        addBtnCons.gridheight = 1;
        addBtnCons.gridwidth = 1;
        addBtnCons.insets = insets;
        addBtnCons.ipadx = 0;
        addBtnCons.ipady = 0;
        addBtnCons.fill = GridBagConstraints.BOTH;
        addBtnCons.anchor = GridBagConstraints.CENTER;

        this.add(addBtn, addBtnCons);

        this.model = new DefaultTableModel() {

            @Override
            public Class<?> getColumnClass(int columnIndex) {

                switch (columnIndex) {
                    case 0:
                        return Boolean.class;
                    case 1:
                        return String.class;
                    case 2:
                        return Boolean.class;
                }

                return super.getColumnClass(columnIndex);
            }

        };
        this.table = new JTable(model);
        this.tableScrollPane = new JScrollPane(table);

        model.addColumn("Enabled");
        model.addColumn("Prefix");
        model.addColumn("Include subdomains?");

        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        table.getColumnModel().getColumn(0).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setPreferredWidth(400);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);

        model.addTableModelListener(this);

        GridBagConstraints tableCons = new GridBagConstraints();
        tableCons.gridx = 0;
        tableCons.gridy = 11;
        tableCons.weightx = 1;
        tableCons.weighty = 1;
        tableCons.gridheight = 3;
        tableCons.gridwidth = 8;
        tableCons.insets = insets;
        tableCons.ipadx = 0;
        tableCons.ipady = 0;
        tableCons.fill = GridBagConstraints.BOTH;
        tableCons.anchor = GridBagConstraints.CENTER;

        this.add(tableScrollPane, tableCons);

        this.removeBtn = new JButton("Remove");

        removeBtn.addActionListener(l -> {

            int sel = table.getSelectedRow();

            if (sel > -1) {

                try {

                    listener.removeScopeItem(sel);

                } catch (Exception e) {

                    JOptionPane.showMessageDialog(
                            SwingUtilities.getWindowAncestor(this),
                            e.getMessage(),
                            "Error",
                            JOptionPane.WARNING_MESSAGE);

                }

            }

        });

        GridBagConstraints removeBtnCons = new GridBagConstraints();
        removeBtnCons.gridx = 6;
        removeBtnCons.gridy = 14;
        removeBtnCons.weightx = .5;
        removeBtnCons.weighty = .5;
        removeBtnCons.gridheight = 1;
        removeBtnCons.gridwidth = 1;
        removeBtnCons.insets = insets;
        removeBtnCons.ipadx = 0;
        removeBtnCons.ipady = 0;
        removeBtnCons.fill = GridBagConstraints.BOTH;
        removeBtnCons.anchor = GridBagConstraints.CENTER;

        this.add(removeBtn, removeBtnCons);

        this.okBtn = new JButton("OK");

        okBtn.addActionListener(l -> {

            SwingUtilities.getWindowAncestor(this).dispose();

        });

        GridBagConstraints okBtnCons = new GridBagConstraints();
        okBtnCons.gridx = 7;
        okBtnCons.gridy = 14;
        okBtnCons.weightx = .5;
        okBtnCons.weighty = .5;
        okBtnCons.gridheight = 1;
        okBtnCons.gridwidth = 1;
        okBtnCons.insets = insets;
        okBtnCons.ipadx = 0;
        okBtnCons.ipady = 0;
        okBtnCons.fill = GridBagConstraints.BOTH;
        okBtnCons.anchor = GridBagConstraints.CENTER;

        this.add(okBtn, okBtnCons);

    }

    public void addScope(ScopeItem item) {

        Object[] o = { item.isEnabled(), item.getPrefix(), item.getIncludeSubdomains() };

        model.addRow(o);

    }

    public void removeScope(int index) {

        model.removeRow(index);

    }

    public void clearInput() {

        prefixField.setText("");
        includeSubdomainsBox.setSelected(false);
        prefixField.grabFocus();

    }

    public void setTools(ArrayList<ToolType> tools) throws Exception {

        for (ToolType tool : tools) {

            switch (tool) {
                case TARGET:
                    targetBox.setSelected(true);
                    break;
                case SCANNER:
                    scannerBox.setSelected(true);
                    break;
                case REPEATER:
                    repeaterBox.setSelected(true);
                    break;
                case INTRUDER:
                    intruderBox.setSelected(true);
                    break;
                case SEQUENCER:
                    sequencerBox.setSelected(true);
                    break;
                case BURP_AI:
                    aiBox.setSelected(true);
                    break;
                case EXTENSIONS:
                    extensionBox.setSelected(true);
                    break;
                case PROXY:
                    proxyBox.setSelected(true);
                    break;
                default:
                    throw new Exception("Invalid tool in scope.");
            }

        }

    }

    public void setPrefixes(ArrayList<ScopeItem> scope, ScopeOption scopeOption) {

        setScopeOption(scopeOption);
        setEntryEnabled(scopeOption);

        model.setRowCount(0);

        if (scope == null)
            return;

        for (ScopeItem s : scope) {

            addScope(s);

        }

    }

    public void setEntryEnabled(ScopeOption scopeOption) {

        switch (scopeOption) {
            case ALL_URLS:
                setEntryEnabled(false);
                break;
            case CUSTOM_SCOPE:
                setEntryEnabled(true);
                break;
            case SUITE_SCOPE:
                setEntryEnabled(false);
                break;
            default:
                logError("Can't set entry enabled for invalid tool type...", false);
                break;
        }

    }

    public void setEntryEnabled(boolean enabled) {

        prefixLbl.setEnabled(enabled);
        prefixField.setEnabled(enabled);
        includeSubdomainsBox.setEnabled(enabled);
        addBtn.setEnabled(enabled);
        table.setEnabled(enabled);
        tableScrollPane.setEnabled(enabled);

    }

    @Override
    public void tableChanged(TableModelEvent e) {

        int column = e.getColumn(), row = e.getFirstRow();

        if (e.getType() == TableModelEvent.UPDATE && row == e.getLastRow()) {

            try {

                Object value = model.getValueAt(row, column);

                switch (e.getColumn()) {

                    case 0:
                        listener.setItemEnabled((boolean) value, row);
                        break;
                    case 1:
                        listener.setItemPrefix((String) value, row);
                        break;
                    case 2:
                        listener.setItemIncludeSubdomains((boolean) value, row);

                }

            } catch (Exception ex) {

                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(this),
                        ex.getMessage(),
                        "Error",
                        JOptionPane.WARNING_MESSAGE);

            }

        }

    }

    @Override
    public void itemStateChanged(ItemEvent e) {

        boolean selected = e.getStateChange() == 1;

        Object item = e.getItem();

        if (item instanceof JCheckBox) {

            switch (((JCheckBox) e.getItem()).getText()) {
                case "Target":
                    listener.setTool(ToolType.TARGET, selected);
                    break;
                case "Scanner":
                    listener.setTool(ToolType.SCANNER, selected);
                    break;
                case "Repeater":
                    listener.setTool(ToolType.REPEATER, selected);
                    break;
                case "Intruder":
                    listener.setTool(ToolType.INTRUDER, selected);
                    break;
                case "Sequencer":
                    listener.setTool(ToolType.SEQUENCER, selected);
                    break;
                case "AI":
                    listener.setTool(ToolType.BURP_AI, selected);
                    break;
                case "Extensions":
                    listener.setTool(ToolType.EXTENSIONS, selected);
                    break;
                case "Proxy (use with caution)":
                    listener.setTool(ToolType.PROXY, selected);
                    break;
            }

        } else if (item instanceof JRadioButton && selected) {

            ScopeOption sel = null;

            switch (((JRadioButton) item).getText()) {

                case "Include all URLs":
                    sel = ScopeOption.ALL_URLS;
                    break;
                case "Use suite scope [defined in Target tab]":
                    sel = ScopeOption.SUITE_SCOPE;
                    break;
                case "Custom scope":
                    sel = ScopeOption.CUSTOM_SCOPE;
                    break;

            }

            setEntryEnabled(sel);
            listener.setScopeOption(sel);

        }

    }

    private void setScopeOption(ScopeOption scopeOption) {

        switch (scopeOption) {

            case CUSTOM_SCOPE:
                customScopeRad.setSelected(true);
                break;
            case SUITE_SCOPE:
                suiteScopeRad.setSelected(true);
                break;
            default:
                allScopeRad.setSelected(true);
                break;

        }

    }

}
