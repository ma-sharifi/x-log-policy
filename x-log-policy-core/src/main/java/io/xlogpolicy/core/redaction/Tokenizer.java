package io.xlogpolicy.core.redaction;

/**
 * Produces a stable surrogate for a sensitive value, for {@link io.xlogpolicy.core.PolicyType#TOKENIZE}.
 *
 * <p>The default implementation derives the token from the configured HMAC key, which keeps values
 * correlatable across log lines without a round trip. Provide a bean of this type to delegate to a real
 * tokenization service instead. Implementations must be thread-safe and must not throw; returning
 * {@code null} falls back to a full mask.
 */
@FunctionalInterface
public interface Tokenizer {

    String tokenize(String value);
}
