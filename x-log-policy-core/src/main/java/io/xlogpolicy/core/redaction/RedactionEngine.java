package io.xlogpolicy.core.redaction;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Applies a {@link FieldPolicy} to a value by dispatching to the matching {@link ValueRedaction}.
 *
 * <p>Nothing here throws: a missing or misbehaving redaction degrades to a full mask, because a broken
 * redaction must never turn into either an exception in the caller or a leak.
 */
public final class RedactionEngine {

    private final Map<String, ValueRedaction> redactions;
    private final RedactionSettings settings;

    /**
     * @param settings   limits and parameters
     * @param tokenizer  tokenizer for {@link PolicyType#TOKENIZE}, {@code null} for the HMAC-derived default
     * @param additional user supplied redactions; a built-in name here replaces that built-in
     */
    public RedactionEngine(RedactionSettings settings, Tokenizer tokenizer, List<ValueRedaction> additional) {
        this.settings = settings;
        Map<String, ValueRedaction> byName = new LinkedHashMap<>();
        for (ValueRedaction redaction : BuiltinRedactions.create(settings, tokenizer)) {
            byName.put(redaction.name(), redaction);
        }
        if (additional != null) {
            for (ValueRedaction redaction : additional) {
                byName.put(redaction.name(), redaction);
            }
        }
        this.redactions = Map.copyOf(byName);
    }

    public static RedactionEngine withDefaults() {
        return new RedactionEngine(RedactionSettings.defaults(), null, List.of());
    }

    public RedactionSettings settings() {
        return settings;
    }

    /** @return the names of every registered redaction, for diagnostics */
    public java.util.Set<String> registeredNames() {
        return redactions.keySet();
    }

    /**
     * Applies {@code policy} to {@code value}.
     *
     * @return the replacement text, or {@code null} when the original value must be written unchanged
     *         ({@link PolicyType#SAFE}) or when there is no value ({@code null} input)
     */
    public String redact(Object value, FieldPolicy policy) {
        if (value == null || policy.isSafe()) {
            return null;
        }
        String lookup = policy.type() == PolicyType.CUSTOM ? policy.customName() : policy.type().name();
        ValueRedaction redaction = redactions.get(lookup);
        if (redaction == null) {
            // An unknown custom redaction must fail closed, not fall through to the raw value.
            return settings.maskToken();
        }
        try {
            String redacted = redaction.redact(value, policy);
            return redacted == null ? settings.maskToken() : redacted;
        } catch (RuntimeException ex) {
            return settings.maskToken();
        }
    }

    /** Truncates a safe string that would otherwise flood the log. */
    public String truncate(String value) {
        int limit = settings.maxStringLength();
        if (limit <= 0 || value == null || value.length() <= limit) {
            return value;
        }
        return value.substring(0, limit) + "…(" + (value.length() - limit) + " more chars)";
    }
}
