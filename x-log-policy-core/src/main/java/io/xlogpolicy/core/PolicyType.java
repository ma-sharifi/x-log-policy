package io.xlogpolicy.core;

import java.util.Locale;
import java.util.Map;

/**
 * The set of redaction policies that can be attached to a field, either through the
 * {@code x-log-policy} OpenAPI extension or through {@link LogPolicy}.
 */
public enum PolicyType {

    /** Value is not sensitive and is logged verbatim. */
    SAFE,

    /** Value is replaced by a fixed mask, e.g. {@code ***}. */
    MASK,

    /** Value keeps its trailing characters, e.g. {@code ************1234}. */
    PARTIAL,

    /** Value is replaced by an unkeyed SHA-256 digest, e.g. {@code sha256:9f86d081}. */
    HASH,

    /** Value is replaced by a keyed HMAC-SHA256 digest, e.g. {@code hmac:7d3a9c12}. */
    HMAC,

    /** Value is replaced by a token obtained from the configured tokenizer. */
    TOKENIZE,

    /** Property is omitted from the output entirely. */
    DROP,

    /** Value is handled by a user supplied redaction, looked up by name. */
    CUSTOM;

    private static final Map<String, PolicyType> ALIASES = Map.of(
            "NONE", SAFE,
            "PLAIN", SAFE,
            "REDACT", MASK,
            "PARTIAL_MASK", PARTIAL,
            "SHA256", HASH,
            "HMAC_SHA256", HMAC,
            "TOKEN", TOKENIZE,
            "OMIT", DROP,
            "REMOVE", DROP);

    /**
     * Parses a policy name as written in an OpenAPI document. Case and {@code -}/{@code _}
     * separators are ignored and a small set of aliases is accepted.
     *
     * @throws IllegalArgumentException if the name is not a known policy
     */
    public static PolicyType parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("x-log-policy value must not be blank");
        }
        String key = raw.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        PolicyType alias = ALIASES.get(key);
        if (alias != null) {
            return alias;
        }
        try {
            return PolicyType.valueOf(key);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unknown x-log-policy value '" + raw + "'. Supported values: "
                    + String.join(", ", java.util.Arrays.stream(values()).map(Enum::name).toList()));
        }
    }
}
