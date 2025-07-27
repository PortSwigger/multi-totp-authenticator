package com.stephensantilli.totp.ui;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ScrollPaneConstants;

import com.stephensantilli.totp.CodeListener;

public class TOTPPane extends JSplitPane {

    private Entry entryPane;

    private CodeTable codeTable;

    public TOTPPane(CodeListener listener) {

        super(VERTICAL_SPLIT);

        setResizeWeight(.05);

        this.entryPane = new Entry(listener);
        this.codeTable = new CodeTable(listener);

        JScrollPane scrollPane = new JScrollPane(codeTable);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

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
