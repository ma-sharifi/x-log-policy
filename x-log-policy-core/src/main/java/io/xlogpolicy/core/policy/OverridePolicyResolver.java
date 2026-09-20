package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Operator supplied overrides, the highest precedence source. They exist so a policy can be tightened
 * (or, in a development environment, relaxed) without rebuilding the service.
 *
 * <p>Keys are {@code Schema.property}, {@code com.example.Type.property}, {@code *.property} or a bare
 * {@code property}; matching is case-insensitive. Values are a policy name, optionally with a
 * parameter: {@code MASK}, {@code PARTIAL:4}, {@code CUSTOM:myRedaction}.
 *
 * <pre>{@code
 * x-log-policy:
 *   overrides:
 *     "[Customer.ssn]": DROP
 *     "[*.email]": HMAC
 * }</pre>
 */
public final class OverridePolicyResolver implements PolicyResolver {

    private final Map<String, FieldPolicy> overrides;

    public OverridePolicyResolver(Map<String, String> rawOverrides) {
        Map<String, FieldPolicy> parsed = new LinkedHashMap<>();
        if (rawOverrides != null) {
            rawOverrides.forEach((key, value) -> parsed.put(normalize(key), parseValue(key, value)));
        }
        this.overrides = Map.copyOf(parsed);
    }

    public static OverridePolicyResolver none() {
        return new OverridePolicyResolver(Map.of());
    }

    public boolean isEmpty() {
        return overrides.isEmpty();
    }

    @Override
    public Optional<FieldPolicy> resolve(PropertyRef property) {
        if (overrides.isEmpty()) {
            return Optional.empty();
        }
        if (property.hasOwner()) {
            Class<?> owner = property.owner();
            for (String name : new String[]{property.name(), property.implicitName()}) {
                FieldPolicy match = lookup(owner.getName() + "." + name);
                if (match == null) {
                    match = lookup(owner.getSimpleName() + "." + name);
                }
                if (match != null) {
                    return Optional.of(match);
                }
            }
        }
        return resolveByFieldName(property.name())
                .or(() -> resolveByFieldName(property.implicitName()));
    }

    @Override
    public Optional<FieldPolicy> resolveByFieldName(String propertyName) {
        FieldPolicy match = lookup("*." + propertyName);
        if (match == null) {
            match = lookup(propertyName);
        }
        return Optional.ofNullable(match);
    }

    @Override
    public String sourceName() {
        return "configuration-override";
    }

    private FieldPolicy lookup(String key) {
        return overrides.get(normalize(key));
    }

    private static String normalize(String key) {
        return key.trim().toLowerCase(Locale.ROOT);
    }

    /** Parses {@code MASK}, {@code PARTIAL:4} or {@code CUSTOM:name}. */
    static FieldPolicy parseValue(String key, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("x-log-policy override '" + key + "' has no value");
        }
        String raw = value.trim();
        int separator = raw.indexOf(':');
        String policyName = separator < 0 ? raw : raw.substring(0, separator);
        String argument = separator < 0 ? "" : raw.substring(separator + 1).trim();
        PolicyType type = PolicyType.parse(policyName);
        return switch (type) {
            case PARTIAL -> argument.isEmpty() ? FieldPolicy.of(PolicyType.PARTIAL)
                    : FieldPolicy.partial(parseKeep(key, argument));
            case CUSTOM -> {
                if (argument.isEmpty()) {
                    throw new IllegalArgumentException(
                            "x-log-policy override '" + key + "' uses CUSTOM but names no redaction (CUSTOM:myName)");
                }
                yield FieldPolicy.custom(argument);
            }
            default -> FieldPolicy.of(type);
        };
    }

    private static int parseKeep(String key, String argument) {
        try {
            int keep = Integer.parseInt(argument);
            if (keep < 0) {
                throw new NumberFormatException(argument);
            }
            return keep;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(
                    "x-log-policy override '" + key + "' has a non numeric PARTIAL length: " + argument);
        }
    }
}
