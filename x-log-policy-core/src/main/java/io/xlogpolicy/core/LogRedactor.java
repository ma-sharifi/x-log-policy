package io.xlogpolicy.core;

/**
 * Renders objects in a form that is safe to log.
 *
 * <p>The contract every implementation must keep: <strong>no method ever throws</strong>. Logging is not
 * allowed to be the reason a request fails, so a failure to redact is reported inside the returned
 * string instead of being propagated.
 *
 * <pre>{@code
 * log.info("created customer {}", redactor.toSafeJson(customer));
 * // created customer {"id":"c-17","email":"hmac:7d3a9c12","ssn":"***"}
 * }</pre>
 */
public interface LogRedactor {

    /** Serializes {@code value} to JSON with every policy applied and the configured limits enforced. */
    String toSafeJson(Object value);

    /** As {@link #toSafeJson(Object)}, truncating the result to {@code maxLength} characters. */
    String toSafeJson(Object value, int maxLength);

    /**
     * Applies the policy of {@code owner.property} to a single value.
     *
     * @return the text to log; the value itself (possibly truncated) when the policy is
     *         {@link PolicyType#SAFE}
     */
    String redactValue(Class<?> owner, String property, Object value);

    /** Applies the policy registered for a bare property name, e.g. an MDC key or a header name. */
    String redactValue(String property, Object value);

    /**
     * Best-effort redaction of text that is already serialized, used by the log framework converters
     * and for payloads of unknown type. Only explicitly declared policies are applied — the default
     * policy is not, since it must not blank out arbitrary log messages.
     */
    String redactText(String text);
}
