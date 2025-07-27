package com.stephensantilli.totp;

/**
 * Copyright (c) 2011 IETF Trust and the persons identified as
 * authors of the code. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted pursuant to, and subject to the license
 * terms contained in, the Simplified BSD License set forth in Section
 * 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
 * (http://trustee.ietf.org/license-info).
 */

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;

/**
 * This code is a modified version of the reference implementation from RFC
 * 6238.
 * 
 * @author Johan Rydell, PortWise, Inc.
 * @see https://datatracker.ietf.org/doc/html/rfc6238#appendix-A
 */
public class Generator {

    private static final int[] DIGITS_POWER
    // 0 1 2 3 4 5 6 7 8
            = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto
     *            the crypto algorithm (HmacSHA1, HmacSHA256,
     *            HmacSHA512)
     * @param keyBytes
     *            the bytes to use for the HMAC key
     * @param text
     *            the message or text to be authenticated
     */
    private static byte[] hmac_sha(String crypto, byte[] keyBytes,
            byte[] text) {

        try {

            Mac hmac;
            hmac = Mac.getInstance(crypto);

            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");

            hmac.init(macKey);

            return hmac.doFinal(text);

        } catch (GeneralSecurityException gse) {

            throw new UndeclaredThrowableException(gse);

        }

    }

    /**
     * This method converts a HEX string to Byte[]
     *
     * @param hex
     *            the HEX string
     * @return a byte array
     */
    private static byte[] hexStr2Bytes(String hex) {

        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];

        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];

        return ret;
    }

    /**
     * This method converts a Base32 string to a Base16 (Hexadecimal) string
     *
     * @param hex
     *            the Base32 string
     * @return a byte array
     */
    private static String base32Str2HexStr(String base32) {

        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        base32 = base32.toUpperCase().replaceAll("[= ]", "");

        int buffer = 0, bitsLeft = 0;
        StringBuilder hex = new StringBuilder();

        for (char c : base32.toCharArray()) {

            int val = alphabet.indexOf(c);
            if (val < 0)
                throw new IllegalArgumentException("Invalid Base32 char: " + c);

            buffer = (buffer << 5) | val;
            bitsLeft += 5;

            while (bitsLeft >= 8) {

                bitsLeft -= 8;
                int b = (buffer >> bitsLeft) & 0xFF;
                hex.append(String.format("%02x", b));

            }

        }

        return hex.toString();

    }

    public static String generateTOTP(String base32Secret, int digits, int duration, String crypto) {

        return generateTOTP(base32Secret, digits, Long.toHexString(System.currentTimeMillis() / 1000 / duration),
                crypto);

    }

    /**
     * Generates a TOTP.
     * 
     * @param base32Secret
     *            The secret key, in Base32
     * @param digits
     *            The number of digits, typically 6 or 8.
     * @param time
     *            The time, in milliseconds, to calculate the TOTP for.
     * @param crypto
     *            The crypto algorithm to use (HmacSHA1, HmacSHA256,
     *            HmacSHA512)
     * @return A time-based one-time password according to RFC 6238 with the
     *         supplied parameters.
     */
    public static String generateTOTP(String base32Secret, int digits, String time, String crypto) {

        String result = null;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        while (time.length() < 16)
            time = "0" + time;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);

        // TODO: This can probably be made more efficient
        byte[] k = hexStr2Bytes(base32Str2HexStr(base32Secret));

        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[digits];

        result = Integer.toString(otp);

        while (result.length() < digits) {

            result = "0" + result;

        }

        return result;

    }

}
