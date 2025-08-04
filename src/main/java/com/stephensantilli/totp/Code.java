package com.stephensantilli.totp;

/**
 * Represents a single TOTP code. This stores all of the information needed to
 * generate and display the code.
 */
public class Code {

    private String name, base32Secret, crypto, match;

    private int digits, duration;

    private boolean enabled;

    public Code(String name, String base32Secret, String match, int digits, int duration,
            String crypto,
            boolean enabled) {

        this.name = name;
        this.base32Secret = base32Secret;
        this.match = match;
        this.digits = digits;
        this.duration = duration;
        this.crypto = crypto;
        this.enabled = enabled;

    }

    /**
     * Checks if two codes are equal based on their name, secret, number of digits,
     * and hashing algorithm.
     * 
     * @param code The code to compare to
     * @return Whether or not the codes are equal
     */
    public boolean equals(Code code) {

        return name.equals(code.getName())
                && base32Secret.equals(code.getBase32Secret())
                && digits == code.getDigits()
                && crypto.equals(code.getCrypto());

    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String generateCode() {

        return Generator.generateTOTP(base32Secret, digits, duration, crypto);

    }

    public String getBase32Secret() {

        return base32Secret;
    }

    public void setBase32Secret(String base32Secret) {

        this.base32Secret = base32Secret;
    }

    public String getCrypto() {

        return crypto;
    }

    public void setCrypto(String crypto) {

        this.crypto = crypto;
    }

    public String getMatch() {

        return match;
    }

    public void setMatch(String regex) {

        this.match = regex;
    }

    public int getDigits() {

        return digits;
    }

    public void setDigits(int digits) {

        this.digits = digits;
    }

    public int getDuration() {

        return duration;
    }

    public void setDuration(int duration) {

        this.duration = duration;

    }

    public boolean isEnabled() {

        return enabled;
    }

    public void setEnabled(boolean enabled) {

        this.enabled = enabled;
    }

    /**
     * Gets this code's {@code otpauth://} URI according to this draft
     * specification: {@link https://linuxgemini.github.io/otpauth-spec-draft/}. If
     * there is a {@code -} in the middle of this code's name, the content on the
     * left side of the dash will be used as the code's {@code label} and the right
     * side will be used as the code's {@code issuer}. This is the URI that is
     * encoded into QR codes.
     * 
     * @return An {@code otpauth://} URI representing this TOTP
     */
    public String getUri() {

        String uri = "otpauth://totp/";

        String label = name,
                issuer = null;

        int separator = label.indexOf("-");

        if (separator > -1 && separator + 1 < label.length()) {

            issuer = label.substring(separator + 1).trim();
            label = label.substring(0, separator);

        }

        String secret = this.base32Secret.replaceAll(" ", "").toUpperCase().trim();
        String algorithm = this.crypto;
        switch (algorithm) {
            case "HmacSHA1":
                algorithm = "SHA1";
                break;
            case "HmacSHA256":
                algorithm = "SHA256";
                break;
            case "HmacSHA512":
                algorithm = "SHA512";
                break;
        }

        uri += label
                + "?secret=" + secret
                + "&algorithm=" + algorithm
                + "&digits=" + digits
                + "&period=" + duration
                + (issuer != null ? "&issuer=" + issuer : "");

        return uri;

    }

}
