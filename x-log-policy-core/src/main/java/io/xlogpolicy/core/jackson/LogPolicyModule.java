package io.xlogpolicy.core.jackson;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.util.Map;

/**
 * Jackson module that applies {@code x-log-policy} redaction during serialization.
 *
 * <p>Register it on a mapper dedicated to logging — never on the mapper that produces HTTP responses,
 * or the API would start returning masked data. {@link io.xlogpolicy.core.JacksonLogRedactor} builds
 * such a mapper for you.
 */
public final class LogPolicyModule extends SimpleModule {

    private static final long serialVersionUID = 1L;

    public LogPolicyModule(PolicyRegistry registry, RedactionEngine engine) {
        super("x-log-policy", new Version(0, 1, 0, null, "io.xlogpolicy", "x-log-policy-core"));
        setSerializerModifier(new PolicySerializerModifier(registry, engine));
        // A map is not a bean, so the modifier never sees it. Without this, logging a
        // Map<String, Object> payload — or any map reached outside a policied property — would print
        // raw values. Keys are resolved by name instead, keeping the fail-closed guarantee intact.
        addSerializer(Map.class, new MapPolicySerializer(registry, engine, null));
    }
}
