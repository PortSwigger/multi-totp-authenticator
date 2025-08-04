package com.stephensantilli.totp;

import com.stephensantilli.totp.ui.CodeItem;
import burp.api.montoya.core.ToolType;

/**
 * Provides methods for the UI to call back to the main {@link TOTP} class.
 */
public interface UIListener {

    /**
     * Removes a {@link CodeItem} from the extension. If persistence is enabled,
     * this will also be reflected in the project store.
     * 
     * @param codeItem The item to delete.
     */
    public void removeCodeItem(CodeItem codeItem);

    /**
     * Adds a TOTP to the extension, saving it to the project store if desired and
     * persistence is enabled.
     * 
     * @param code The {@link Code} to add
     * @param save Whether or not to save the code to the project store. This does
     *             nothing if persistence is not enabled.
     * @throws Exception If the code cannot be added, such as when there is already
     *                   a code with the same name
     */
    public void addCode(Code code, boolean save) throws Exception;

    /**
     * Updates the match string for a {@link Code} and highlights any duplicate
     * match strings in the UI. If persistence is enabled, this will
     * also be reflected in the project store.
     * 
     * @param code  The Code to update
     * @param match The new match string
     */
    public void matchUpdate(Code code, String match);

    /**
     * Sets whether or not matching is enabled for a code. If persistence is
     * enabled, this will also be reflected in the project store.
     * 
     * @param code    The code to enable or disable matching for
     * @param enabled Whether or not matching is enabled or disabled
     */
    public void setCodeEnabled(Code code, boolean enabled);

    /**
     * Adds an item to the scope of the extension in this project. If persistence is
     * enabled, this will also be reflected in the project store.
     * 
     * @param item The item to add
     * @throws Exception If there is already a scope item with the same prefix
     */
    public void addScopeItem(ScopeItem item) throws Exception;

    /**
     * Removes an item from the scope of the extension in this project. If
     * persistence is enabled, this will also be reflected in the project store.
     * 
     * @param index The index of the {@link ScopeItem} to remove in the
     *              {@link UIListener}'s list of scope items.
     * @throws IndexOutOfBoundsException If the provided index is not in the list of
     *                                   scope items.
     */
    public void removeScopeItem(int index) throws IndexOutOfBoundsException;

    /**
     * Sets whether a tool is included in the extension's scope. If persistence is
     * enabled, this will also be reflected in the project store.
     * 
     * @param tool    The {@link ToolType} to update
     * @param enabled Whether or not the tool is in scope
     */
    public void setTool(ToolType tool, boolean enabled);

    /**
     * Sets the {@link ScopeOption} used by the extension.
     * 
     * @param scopeOption The {@link ScopeOption} to use.
     */
    public void setScopeOption(ScopeOption scopeOption);

    /**
     * Opens the scope configuration dialog.
     * 
     * @throws Exception If there is an error during the setup of the dialog
     * @see {@link com.stephensantilli.totp.ui.ScopeDialog}
     */
    public void openScopeDialog() throws Exception;

    /**
     * Closes the active scope dialog.
     * 
     * @see {@link com.stephensantilli.totp.ui.ScopeDialog}
     */
    public void closeScopeDialog();

    /**
     * Sets the prefix of a {@link ScopeItem}. If persistence is enabled,
     * this will also be reflected in the project store.
     * 
     * @param prefix The new prefix
     * @param index  The index of the {@link ScopeItem} to be updated in the
     *               {@link UIListener}'s list of scope items.
     * @throws IndexOutOfBoundsException If the index of the item is out of bounds
     *                                   in the {@link UIListener}'s list of scope
     *                                   items.
     * @see ScopeItem#getPrefix()
     */
    public void setItemPrefix(String prefix, int index) throws IndexOutOfBoundsException;

    /**
     * Sets whether a {@link ScopeItem} is enabled. If persistence is
     * enabled, this will also be reflected in the project store.
     * 
     * @param enabled Whether or not the item is enabled
     * @param index   The index of the {@link ScopeItem} to be updated in the
     *                {@link UIListener}'s list of scope items.
     * @throws IndexOutOfBoundsException If the index of the item is out of bounds
     *                                   in the {@link UIListener}'s list of scope
     *                                   items.
     * @see ScopeItem#isEnabled()
     */
    public void setItemEnabled(boolean enabled, int index) throws IndexOutOfBoundsException;

    /**
     * Sets whether a {@link ScopeItem} includes its subdomains. If persistence is
     * enabled, this will also be reflected in the project store.
     * 
     * @param includeSubdomains Whether or not subdomains will be included
     * @param index             The index of the {@link ScopeItem} to be updated in
     *                          the
     *                          {@link UIListener}'s list of scope items.
     * @throws IndexOutOfBoundsException If the index of the item is out of bounds
     *                                   in the {@link UIListener}'s list of scope
     *                                   items.
     * @see ScopeItem#getIncludeSubdomains()
     */
    public void setItemIncludeSubdomains(boolean includeSubdomains, int index) throws IndexOutOfBoundsException;

}