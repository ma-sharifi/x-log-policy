package io.xlogpolicy.core.fixtures;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.JacksonLogRedactor;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;
import io.xlogpolicy.core.redaction.ValueRedaction;

import java.util.List;
import java.util.Map;

/** Builds redactors for tests with a fixed HMAC key, so digests are reproducible. */
public final class Redactors {

    /** A custom redaction, to prove the CUSTOM policy dispatches by name. */
    public static final ValueRedaction INITIALS = new ValueRedaction() {
        @Override
        public String name() {
            return "initials";
        }

        @Override
        public String redact(Object value, FieldPolicy policy) {
            StringBuilder initials = new StringBuilder();
            for (String part : String.valueOf(value).split("\\s+")) {
                if (!part.isEmpty()) {
                    initials.append(Character.toUpperCase(part.charAt(0))).append('.');
                }
            }
            return initials.toString();
        }
    };

    private Redactors() {
    }

    public static RedactionSettings settings() {
        return RedactionSettings.builder().hmacSecret("test-key-do-not-use-in-production").build();
    }

    public static RedactionEngine engine() {
        return new RedactionEngine(settings(), null, List.of(INITIALS));
    }

    /** Annotations only, fail-closed default. */
    public static JacksonLogRedactor standard() {
        return new JacksonLogRedactor(
                PolicyRegistry.annotationsOnly(FieldPolicy.of(PolicyType.MASK)), engine());
    }

    /** Annotations only, with the default policy replaced (e.g. a fail-open deployment). */
    public static JacksonLogRedactor withDefaultPolicy(PolicyType defaultPolicy) {
        return new JacksonLogRedactor(
                PolicyRegistry.annotationsOnly(FieldPolicy.of(defaultPolicy)), engine());
    }

    /** The full chain: overrides, annotations, OpenAPI metadata. */
    public static JacksonLogRedactor withChain(Map<String, String> overrides, LogPolicyMetadata metadata) {
        return new JacksonLogRedactor(
                PolicyRegistry.standard(overrides, metadata, FieldPolicy.of(PolicyType.MASK)), engine());
    }

    public static JacksonLogRedactor withSettings(RedactionSettings settings) {
        return new JacksonLogRedactor(
                PolicyRegistry.annotationsOnly(FieldPolicy.of(PolicyType.MASK)),
                new RedactionEngine(settings, null, List.of(INITIALS)));
    }
}
