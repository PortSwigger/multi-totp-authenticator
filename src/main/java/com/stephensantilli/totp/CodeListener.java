package com.stephensantilli.totp;

import com.stephensantilli.totp.ui.CodeItem;
import burp.api.montoya.core.ToolType;

public interface CodeListener {

    public void removeCode(CodeItem codeItem);

    public void addCode(Code code, boolean save) throws Exception;

    public void matchUpdate(Code code, String regex);

    public void setEnabled(Code code, boolean enabled);

    public void addScope(ScopeItem item) throws Exception;

    public void removeScope(int index) throws Exception;

    public void setTool(ToolType tool, boolean enabled);

    public void setScopeOption(ScopeOption scopeOption);

    public void openScopeDialog() throws Exception;

    public void closeScopeDialog();

    public void setItemPrefix(String prefix, int index) throws Exception;

    public void setItemEnabled(boolean enabled, int index) throws Exception;

    public void setItemIncludeSubdomains(boolean includeSubdomains, int index) throws Exception;

}