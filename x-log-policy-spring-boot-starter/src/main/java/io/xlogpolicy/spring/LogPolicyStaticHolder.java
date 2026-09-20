package io.xlogpolicy.spring;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.JacksonLogRedactor;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.metadata.PolicyMetadataIO;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Static access to the redactor, for code the container does not build.
 *
 * <p>Log framework pattern converters are instantiated by Logback or Log4j2, long before (and sometimes
 * entirely without) a Spring context. So the holder bootstraps a standalone redactor from the classpath
 * registry on first use, and the auto-configuration upgrades it to the configured one once the context
 * is up. Application code should inject {@link LogRedactor} instead of calling this.
 */
public final class LogPolicyStaticHolder {

    private static volatile LogRedactor redactor;

    private LogPolicyStaticHolder() {
    }

    /** Installs the context's redactor. Called by the auto-configuration. */
    public static void set(LogRedactor configured) {
        redactor = configured;
    }

    /** Drops the installed redactor, so the next call bootstraps again. Intended for tests. */
    public static void reset() {
        redactor = null;
    }

    /** @return the configured redactor, or a standalone one built from the classpath registry */
    public static LogRedactor get() {
        LogRedactor current = redactor;
        if (current == null) {
            synchronized (LogPolicyStaticHolder.class) {
                current = redactor;
                if (current == null) {
                    current = bootstrap();
                    redactor = current;
                }
            }
        }
        return current;
    }

    private static LogRedactor bootstrap() {
        List<String> problems = new ArrayList<>();
        ClassLoader loader = Thread.currentThread().getContextClassLoader() != null
                ? Thread.currentThread().getContextClassLoader()
                : LogPolicyStaticHolder.class.getClassLoader();
        LogPolicyMetadata metadata = PolicyMetadataIO.loadAll(loader, problems);
        RedactionSettings settings = RedactionSettings.defaults();
        PolicyRegistry registry = PolicyRegistry.standard(Map.of(), metadata, FieldPolicy.of(PolicyType.MASK));
        return new JacksonLogRedactor(registry, new RedactionEngine(settings, null, List.of()));
    }
}
