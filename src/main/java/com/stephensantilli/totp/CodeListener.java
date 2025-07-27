package com.stephensantilli.totp;

import com.stephensantilli.totp.ui.CodeItem;

public interface CodeListener {

    public void removeCode(CodeItem codeItem);

    public void addCode(Code code, boolean save) throws Exception;

    public void matchUpdate(Code code, String regex);

    public void setEnabled(Code code, boolean enabled);

}
