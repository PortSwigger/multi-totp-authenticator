package com.stephensantilli.totp.ui;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ScrollPaneConstants;

import com.stephensantilli.totp.UIListener;

/**
 * The parent UI element for the extension's Burp Suite tab.
 */
public class TOTPPane extends JSplitPane {

    private Entry entryPane;

    private CodeTable codeTable;

    public TOTPPane(UIListener listener) {

        super(VERTICAL_SPLIT);

        setResizeWeight(.05);

        this.entryPane = new Entry(listener);
        this.codeTable = new CodeTable(listener);

        JScrollPane scrollPane = new JScrollPane(codeTable);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(20);
        scrollPane.getVerticalScrollBar().setUnitIncrement(20);

        this.add(entryPane);
        this.add(scrollPane);

    }

    public Entry getEntryPane() {

        return entryPane;

    }

    public CodeTable getCodeTable() {

        return codeTable;

    }

}
