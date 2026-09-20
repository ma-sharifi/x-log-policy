package io.xlogpolicy.core.text;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redacts {@code "field": value} pairs inside text that has already been serialized — a request body of
 * unknown type, a third-party JSON string, a log message someone built by hand.
 *
 * <p>This is a safety net, not a guarantee: it can only recognise JSON-shaped pairs, and it applies only
 * <em>explicitly declared</em> policies. The default (fail-closed) policy is deliberately not applied
 * here, because doing so would blank out every unrelated log message. Structured objects should go
 * through {@link io.xlogpolicy.core.LogRedactor#toSafeJson(Object)}, which is exhaustive.
 */
public final class TextRedactor {

    /** Output the built-in redactions produce, which must not be redacted a second time. */
    private static final Pattern ALREADY_REDACTED = Pattern.compile(
            "^(\\*+.*|hmac:[0-9a-f]+|sha256:[0-9a-f]+|tok_[0-9a-f]+)$");

    /** {@code "name" : <string | number | boolean | null>} */
    private static final Pattern JSON_PAIR = Pattern.compile(
            "\"([A-Za-z_$][\\w$.\\-]*)\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|-?\\d+(?:\\.\\d+)?(?:[eE][-+]?\\d+)?|true|false|null)");

    private final PolicyRegistry registry;
    private final RedactionEngine engine;

    public TextRedactor(PolicyRegistry registry, RedactionEngine engine) {
        this.registry = registry;
        this.engine = engine;
    }

    /** @return {@code text} with the values of policied fields replaced */
    public String redact(String text) {
        if (text == null || text.isEmpty() || text.indexOf('"') < 0) {
            return text;
        }
        Matcher matcher = JSON_PAIR.matcher(text);
        StringBuilder out = null;
        int copiedUpTo = 0;
        while (matcher.find()) {
            String field = matcher.group(1);
            String rawValue = matcher.group(2);
            Optional<FieldPolicy> policy = registry.resolveExplicitByFieldName(field);
            if (policy.isEmpty() || policy.get().isSafe() || "null".equals(rawValue)) {
                continue;
            }
            String current = unquote(rawValue);
            // Messages often contain output that already went through the redactor. Re-applying a policy
            // there would corrupt it — PARTIAL, HASH and HMAC are not idempotent — so leave it alone.
            if (current.equals(engine.settings().maskToken()) || ALREADY_REDACTED.matcher(current).matches()) {
                continue;
            }
            if (out == null) {
                out = new StringBuilder(text.length() + 16);
            }
            out.append(text, copiedUpTo, matcher.start(2));
            out.append('"').append(escape(replacement(rawValue, policy.get()))).append('"');
            copiedUpTo = matcher.end(2);
        }
        if (out == null) {
            return text;
        }
        return out.append(text, copiedUpTo, text.length()).toString();
    }

    private String replacement(String rawValue, FieldPolicy policy) {
        String value = unquote(rawValue);
        // A key cannot be removed from free-form text without risking malformed output, so DROP masks.
        FieldPolicy effective = policy.isDrop() ? FieldPolicy.of(PolicyType.MASK) : policy;
        String redacted = engine.redact(value, effective);
        return redacted == null ? value : redacted;
    }

    private static String unquote(String rawValue) {
        if (rawValue.length() >= 2 && rawValue.charAt(0) == '"') {
            return rawValue.substring(1, rawValue.length() - 1)
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\");
        }
        return rawValue;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
