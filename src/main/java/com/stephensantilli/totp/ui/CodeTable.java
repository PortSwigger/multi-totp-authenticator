package com.stephensantilli.totp.ui;

import java.util.ArrayList;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

import com.stephensantilli.totp.Code;
import com.stephensantilli.totp.UIListener;

public class CodeTable extends JPanel {

    private ArrayList<CodeItem> codeItems;

    private UIListener listener;

    public CodeTable(UIListener listener) {

        this.codeItems = new ArrayList<>();
        this.listener = listener;

        BoxLayout layout = new BoxLayout(this, BoxLayout.Y_AXIS);
        setLayout(layout);

    }

    public void updateCodes() {

        for (CodeItem codeItem : codeItems) {
            codeItem.updateCode();
        }

    }

    public void addCode(Code code) {

        CodeItem newCode = new CodeItem(code, listener);

        codeItems.add(newCode);
        this.add(newCode);

        revalidate();
        repaint();

    }

    public void removeCode(CodeItem codeItem) {

        remove(codeItem);
        codeItems.remove(codeItem);

        revalidate();
        repaint();

    }

    public void highlightMatches() {

        ArrayList<CodeItem> items = new ArrayList<>(codeItems);
        items.sort((a, b) -> a.getCode().getMatch().compareTo(b.getCode().getMatch()));

        if (items.size() > 0)
            items.get(0).setRegexValid(true);

        for (int i = 0; i < items.size() - 1; i++) {

            CodeItem item = items.get(i);
            CodeItem next = items.get(i + 1);

            if (item.getCode().getMatch().equals(next.getCode().getMatch())) {

                item.setRegexValid(false);
                next.setRegexValid(false);

            } else {

                next.setRegexValid(true);

            }

        }

    }

}
