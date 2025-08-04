package com.stephensantilli.totp.ui;

import java.util.ArrayList;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

import com.stephensantilli.totp.Code;
import com.stephensantilli.totp.UIListener;

/**
 * The UI element that displays a "table" of TOTP codes the user has added.
 * 
 * @see CodeItem
 */
public class CodeTable extends JPanel {

    private ArrayList<CodeItem> codeItems;

    private UIListener listener;

    public CodeTable(UIListener listener) {

        this.codeItems = new ArrayList<>();
        this.listener = listener;

        BoxLayout layout = new BoxLayout(this, BoxLayout.Y_AXIS);
        setLayout(layout);

    }

    /**
     * Updates the TOTP and progress bar of each {@link CodeItem}. This does not
     * highlight any matching regex strings.
     * 
     * @see #highlightMatches()
     */
    public void updateCodes() {

        for (CodeItem codeItem : codeItems) {
            codeItem.updateCode();
        }

    }

    /**
     * Adds a {@link CodeItem} to the table. Revalidates and repaints the panel.
     * 
     * @param code The item to add.
     */
    public void addCode(Code code) {

        CodeItem newCode = new CodeItem(code, listener);

        codeItems.add(newCode);
        this.add(newCode);

        revalidate();
        repaint();

    }

    /**
     * Removes a {@link CodeItem} from the table. Revalidates and repaints the
     * panel.
     * 
     * @param codeItem The item to remove
     */
    public void removeCode(CodeItem codeItem) {

        remove(codeItem);
        codeItems.remove(codeItem);

        revalidate();
        repaint();

    }

    /**
     * Checks the {@link Code#getMatch()} of each {@link CodeItem} for duplicates
     * and highlights any offending match strings.
     */
    public void highlightMatches() {

        if (codeItems.size() <= 0)
            return;

        ArrayList<CodeItem> items = new ArrayList<>(codeItems);

        items.sort((a, b) -> a.getCode().getMatch().compareTo(b.getCode().getMatch()));

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
