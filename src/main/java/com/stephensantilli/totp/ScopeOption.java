package com.stephensantilli.totp;

/**
 * Enumerates the three options given to a user to control which requests the
 * extension will check for matches.
 * 
 * @see Scope
 */
public enum ScopeOption {

    ALL_URLS(0),
    SUITE_SCOPE(1),
    CUSTOM_SCOPE(2);

    public static ScopeOption valueOf(int value) throws Exception {

        switch (value) {
            case 0:
                return ALL_URLS;
            case 1:
                return SUITE_SCOPE;
            case 2:
                return CUSTOM_SCOPE;
            default:
                throw new Exception("Invalid scope option.");
        }

    }

    private final int value;

    ScopeOption(int value) {

        this.value = value;

    }

    public int getValue() {

        return this.value;

    }

}
