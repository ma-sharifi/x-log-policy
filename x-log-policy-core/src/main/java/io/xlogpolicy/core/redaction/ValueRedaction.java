package io.xlogpolicy.core.redaction;

import io.xlogpolicy.core.FieldPolicy;

/**
 * Turns a sensitive value into something safe to log.
 *
 * <p>Implementations are looked up by {@link #name()}: the built-ins are named after their
 * {@link io.xlogpolicy.core.PolicyType}, while a redaction for {@code PolicyType.CUSTOM} is named by
 * whatever {@code @LogPolicy(value = CUSTOM, name = "...")} declares. Registering a bean of this type
 * with a built-in name replaces that built-in.
 *
 * <p>Implementations must be thread-safe, must never return {@code null} and must never throw.
 */
public interface ValueRedaction {

    /** Lookup name: a {@code PolicyType} name for built-ins, or a custom redaction name. */
    String name();

    /**
     * @param value  the value to redact, never {@code null}
     * @param policy the resolved policy, carrying parameters such as {@code keep}
     * @return the replacement to log
     */
    String redact(Object value, FieldPolicy policy);
}
