package com.stephensantilli.totp;

/**
 * Represents a user-entered URL prefix and its associated options. Instances of
 * this are kept in a {@link Scope}.
 */
public class ScopeItem {

    private String prefix;
    private boolean includeSubdomains, enabled;

    public ScopeItem(String prefix, boolean includeSubdomains, boolean enabled) {
        this.enabled = true;
        this.prefix = prefix;
        this.includeSubdomains = includeSubdomains;
    }

    public boolean isInScope(String url) {

        String base = this.prefix.toLowerCase().replaceFirst("^https?://", "");
        String test = url.toLowerCase().replaceFirst("^https?://", "");

        int basePathStart = base.indexOf("/"), testPathStart = test.indexOf("/");

        if (basePathStart > -1)
            base = base.substring(0, basePathStart);

        if (testPathStart > -1)
            test = test.substring(0, testPathStart);

        if (!includeSubdomains) {

            return test.startsWith(base);

        } else {

            return test.startsWith(base) || test.endsWith("." + base);

        }

    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String url) {
        this.prefix = url;
    }

    public boolean getIncludeSubdomains() {
        return includeSubdomains;
    }

    public void setIncludeSubdomains(boolean includeSubdomains) {
        this.includeSubdomains = includeSubdomains;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

}
