package io.mosip.certify.vault;

import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pure helpers for the credential vault (JDK only). */
public final class VaultUtils {

    private static final Pattern OBJECT = Pattern.compile("\\{[^{}]*\\}");
    private static final Pattern NUMBER = Pattern.compile("['\"]number['\"]\\s*:\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern PRIMARY = Pattern.compile("['\"]is_primary['\"]\\s*:\\s*(?:True|true)");

    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");

    // 32 symbols without I/O/0/1: the code is read off a card and typed on a phone.
    private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Shape of a claim code: XXXX-XXXX-XXXX */
    public static final Pattern CLAIM_CODE = Pattern.compile("[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}");

    private VaultUtils() {}

    /** A short, typeable credential id such as K7QM-2XPD-9TVR (60 bits of randomness). */
    public static String generateClaimCode() {
        StringBuilder sb = new StringBuilder(14);
        for (int i = 0; i < 12; i++) {
            if (i == 4 || i == 8) {
                sb.append('-');
            }
            sb.append(CODE_ALPHABET.charAt(RANDOM.nextInt(CODE_ALPHABET.length())));
        }
        return sb.toString();
    }

    /**
     * Picks the phone to send OTPs to from a `phoneNumbers` claim. Accepts the Python-repr string the
     * registry sends ("[{'type': 'personal', 'number': '+2519...', 'is_primary': True}]"), JSON text,
     * or a bare number. Prefers the entry flagged is_primary, otherwise the first one.
     */
    public static String primaryPhone(Object raw) {
        if (raw == null) {
            return null;
        }
        String text = String.valueOf(raw).trim();
        if (text.isEmpty() || "null".equals(text)) {
            return null;
        }
        String first = null;
        Matcher objects = OBJECT.matcher(text);
        while (objects.find()) {
            String obj = objects.group();
            Matcher number = NUMBER.matcher(obj);
            if (!number.find()) {
                continue;
            }
            String phone = clean(number.group(1));
            if (phone == null) {
                continue;
            }
            if (PRIMARY.matcher(obj).find()) {
                return phone;
            }
            if (first == null) {
                first = phone;
            }
        }
        if (first != null) {
            return first;
        }
        return (text.startsWith("[") || text.startsWith("{")) ? null : clean(text);
    }

    /**
     * Picks the email to send OTPs to from an email claim. Accepts a plain address, a list of addresses, or
     * a list of objects such as "[{'type': 'personal', 'email': 'a@b.com', 'is_primary': True}]" (Python
     * repr or JSON). Prefers the entry flagged is_primary, otherwise the first address found.
     */
    public static String primaryEmail(Object raw) {
        if (raw == null) {
            return null;
        }
        String text = String.valueOf(raw).trim();
        if (text.isEmpty() || "null".equals(text)) {
            return null;
        }
        String first = null;
        Matcher objects = OBJECT.matcher(text);
        while (objects.find()) {
            String obj = objects.group();
            Matcher email = EMAIL.matcher(obj);
            if (!email.find()) {
                continue;
            }
            if (PRIMARY.matcher(obj).find()) {
                return email.group();
            }
            if (first == null) {
                first = email.group();
            }
        }
        if (first != null) {
            return first;
        }
        Matcher any = EMAIL.matcher(text); // plain string, or a list of strings
        return any.find() ? any.group() : null;
    }

    /** 'ronald@example.com' -> 'r***@example.com' (safe to log and show). */
    public static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return null;
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        return email.charAt(0) + "***" + email.substring(at);
    }

    static String clean(String value) {
        StringBuilder sb = new StringBuilder();
        for (char ch : value.toCharArray()) {
            if (Character.isDigit(ch) || ch == '+') {
                sb.append(ch);
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /** '+251959031795' -> '+251*****795' (safe to log). */
    public static String maskPhone(String phone) {
        if (phone == null || phone.isEmpty()) {
            return null;
        }
        if (phone.length() <= 7) {
            return "*".repeat(phone.length());
        }
        return phone.substring(0, 4) + "*".repeat(phone.length() - 7) + phone.substring(phone.length() - 3);
    }
}
