package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;

import java.util.Map;

/**
 * Parses the value of an {@code x-log-policy} declaration, in either of its two forms:
 *
 * <pre>
 * x-log-policy: MASK
 * x-log-policy: { policy: PARTIAL, keep: 4 }
 * </pre>
 *
 * <p>Shared by every schema language that carries the extension — OpenAPI and Avro read the same
 * declaration into the same {@link FieldPolicy}, so a policy cannot mean one thing in an API and another
 * in an event.
 */
public final class PolicyParser {

    /** Extension key, matched case-insensitively because tooling likes to rewrite casing. */
    public static final String EXTENSION = "x-log-policy";

    private PolicyParser() {
    }

    /**
     * @param raw a policy name, or a map with {@code policy}, {@code keep}, {@code name} and {@code params}
     * @throws IllegalArgumentException when the declaration is malformed
     */
    public static FieldPolicy parse(Object raw) {
        if (raw instanceof CharSequence text) {
            return FieldPolicy.of(PolicyType.parse(text.toString()));
        }
        if (raw instanceof Map<?, ?> map) {
            Object policy = firstOf(map, "policy", "value", "type");
            if (policy == null) {
                throw new IllegalArgumentException(EXTENSION + " object form requires a 'policy' entry");
            }
            PolicyType type = PolicyType.parse(String.valueOf(policy));
            int keep = FieldPolicy.KEEP_UNSET;
            Object keepValue = firstOf(map, "keep", "keepLast", "visible");
            if (keepValue != null) {
                try {
                    keep = Integer.parseInt(String.valueOf(keepValue).trim());
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException(EXTENSION + " 'keep' must be a number, got " + keepValue);
                }
                if (keep < 0) {
                    throw new IllegalArgumentException(EXTENSION + " 'keep' must not be negative");
                }
            }
            Object name = firstOf(map, "name", "redaction");
            Object params = map.get("params");
            @SuppressWarnings("unchecked")
            Map<String, Object> extra = params instanceof Map ? (Map<String, Object>) params : Map.of();
            return new FieldPolicy(type, keep, name == null ? "" : String.valueOf(name), extra);
        }
        throw new IllegalArgumentException(EXTENSION + " must be a policy name or an object, got "
                + (raw == null ? "null" : raw.getClass().getSimpleName()));
    }

    private static Object firstOf(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }
}
