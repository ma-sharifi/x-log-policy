package io.xlogpolicy.core;

import java.util.Map;
import java.util.Objects;

/**
 * A resolved policy for a single property: the policy type plus its parameters.
 *
 * @param type       policy to apply, never {@code null}
 * @param keep       trailing characters kept by {@link PolicyType#PARTIAL}, {@code -1} when unset
 * @param customName redaction name for {@link PolicyType#CUSTOM}, empty when unused
 * @param params     extra parameters carried over from the spec, never {@code null}
 */
public record FieldPolicy(PolicyType type, int keep, String customName, Map<String, Object> params) {

    public static final int KEEP_UNSET = -1;

    public FieldPolicy {
        Objects.requireNonNull(type, "type");
        customName = customName == null ? "" : customName;
        params = params == null ? Map.of() : Map.copyOf(params);
        if (type == PolicyType.CUSTOM && customName.isBlank()) {
            throw new IllegalArgumentException("PolicyType.CUSTOM requires a redaction name");
        }
    }

    public static FieldPolicy of(PolicyType type) {
        return new FieldPolicy(type, KEEP_UNSET, "", Map.of());
    }

    public static FieldPolicy partial(int keep) {
        return new FieldPolicy(PolicyType.PARTIAL, keep, "", Map.of());
    }

    public static FieldPolicy custom(String name) {
        return new FieldPolicy(PolicyType.CUSTOM, KEEP_UNSET, name, Map.of());
    }

    /** Builds a policy from an annotation occurrence. */
    public static FieldPolicy from(LogPolicy annotation) {
        return new FieldPolicy(annotation.value(), annotation.keep(), annotation.name(), Map.of());
    }

    public boolean isSafe() {
        return type == PolicyType.SAFE;
    }

    public boolean isDrop() {
        return type == PolicyType.DROP;
    }

    public int keepOrDefault(int fallback) {
        return keep == KEEP_UNSET ? fallback : keep;
    }
}
