package io.xlogpolicy.maven;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Name patterns that suggest a field carries personal data. They exist to catch the field somebody adds
 * to the spec next year and forgets to police — the review that no human reliably does.
 *
 * <p>Matching is on the property name, case-insensitively, as a substring. Patterns are regular
 * expressions so a project can be as precise as it likes.
 */
final class PiiHeuristics {

    /** Conservative defaults: names that are personal data in almost any domain. */
    static final List<String> DEFAULT_PATTERNS = List.of(
            "ssn", "socialsecurity", "nationalid", "passport", "taxid", "vat",
            "iban", "bban", "bic", "swift", "accountnumber", "cardnumber", "pan", "cvv", "cvc", "expiry",
            "email", "mail", "phone", "mobile", "msisdn", "fax",
            "firstname", "lastname", "surname", "fullname", "givenname", "familyname", "maidenname",
            "birth", "dob", "age", "gender", "nationality", "ethnicity", "religion",
            "address", "street", "postcode", "postalcode", "zip", "housenumber",
            "password", "passwd", "secret", "token", "apikey", "credential", "pin", "otp",
            "licence", "license", "driverlicense", "plate",
            "latitude", "longitude", "geolocation",
            "medical", "diagnosis", "health", "insurance", "biometric");

    private final List<Pattern> patterns;
    private final List<Pattern> excludes;

    PiiHeuristics(List<String> patterns, List<String> excludes) {
        this.patterns = compile(patterns == null || patterns.isEmpty() ? DEFAULT_PATTERNS : patterns);
        this.excludes = compile(excludes == null ? List.of() : excludes);
    }

    private static List<Pattern> compile(List<String> raw) {
        List<Pattern> compiled = new ArrayList<>(raw.size());
        for (String pattern : raw) {
            compiled.add(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
        }
        return compiled;
    }

    /**
     * @param qualifiedName {@code Schema.property}, used for exclusions
     * @param propertyName  the property name on its own, used for detection
     * @return the pattern that flagged this name, if any
     */
    Optional<String> flag(String qualifiedName, String propertyName) {
        String normalized = propertyName.toLowerCase(Locale.ROOT).replace("_", "").replace("-", "");
        for (Pattern exclude : excludes) {
            if (exclude.matcher(qualifiedName).find() || exclude.matcher(propertyName).find()) {
                return Optional.empty();
            }
        }
        for (Pattern pattern : patterns) {
            if (pattern.matcher(normalized).find()) {
                return Optional.of(pattern.pattern());
            }
        }
        return Optional.empty();
    }
}
