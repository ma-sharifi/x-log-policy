package io.xlogpolicy.core;

import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamWriteConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import io.xlogpolicy.core.jackson.LogPolicyModule;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.policy.PropertyRef;
import io.xlogpolicy.core.redaction.RedactionEngine;
import io.xlogpolicy.core.text.TextRedactor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default {@link LogRedactor}: a Jackson mapper of its own, carrying the {@link LogPolicyModule}.
 *
 * <p>The mapper is deliberately separate from the application's mapper. Sharing one would mean HTTP
 * responses start coming back masked, so this class never touches the caller's mapper — not even a
 * copy of it is required.
 *
 * <p>Two safety properties are load-bearing:
 * <ul>
 *   <li>nothing thrown: any serialization failure becomes {@code {"_redactionError":...}};</li>
 *   <li>bounded output: depth is capped by the stream write constraints and length by
 *       {@code maxJsonLength}, so a cyclic or enormous object graph cannot take the process down.</li>
 * </ul>
 */
public final class JacksonLogRedactor implements LogRedactor {

    private static final Logger log = LoggerFactory.getLogger(JacksonLogRedactor.class);

    private final PolicyRegistry registry;
    private final RedactionEngine engine;
    private final RedactionSettings settings;
    private final TextRedactor textRedactor;
    private final ObjectWriter writer;

    public JacksonLogRedactor(PolicyRegistry registry, RedactionEngine engine) {
        this.registry = registry;
        this.engine = engine;
        this.settings = engine.settings();
        this.textRedactor = new TextRedactor(registry, engine);
        this.writer = buildWriter(registry, engine, settings);
    }

    /** A redactor wired from annotations only, with default settings. Handy in tests and plain Java. */
    public static JacksonLogRedactor withDefaults() {
        RedactionEngine engine = RedactionEngine.withDefaults();
        return new JacksonLogRedactor(PolicyRegistry.annotationsOnly(FieldPolicy.of(PolicyType.MASK)), engine);
    }

    private static ObjectWriter buildWriter(PolicyRegistry registry, RedactionEngine engine,
                                            RedactionSettings settings) {
        JsonFactory factory = JsonFactory.builder()
                .streamWriteConstraints(StreamWriteConstraints.builder()
                        .maxNestingDepth(settings.maxDepth())
                        .build())
                .build();
        ObjectMapper mapper = new ObjectMapper(factory);
        // Picks up jackson-datatype-jsr310 and friends when present, so safe date fields render properly.
        mapper.findAndRegisterModules();
        mapper.registerModule(new LogPolicyModule(registry, engine));
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        mapper.disable(SerializationFeature.FAIL_ON_SELF_REFERENCES);
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        // Log arbitrary objects, not just ones with getters; policies still decide what is readable.
        mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        return settings.prettyPrint() ? mapper.writerWithDefaultPrettyPrinter() : mapper.writer();
    }

    @Override
    public String toSafeJson(Object value) {
        return toSafeJson(value, settings.maxJsonLength());
    }

    @Override
    public String toSafeJson(Object value, int maxLength) {
        if (value == null) {
            return "null";
        }
        try {
            return clip(writer.writeValueAsString(value), maxLength);
        } catch (Exception | StackOverflowError failure) {
            return failurePlaceholder(value, failure);
        }
    }

    @Override
    public String redactValue(Class<?> owner, String property, Object value) {
        FieldPolicy policy = registry.resolve(PropertyRef.of(owner, property));
        return applyToSingleValue(value, policy);
    }

    @Override
    public String redactValue(String property, Object value) {
        return applyToSingleValue(value, registry.resolveByFieldName(property));
    }

    @Override
    public String redactText(String text) {
        try {
            return textRedactor.redact(text);
        } catch (RuntimeException | StackOverflowError failure) {
            // Never hand back text we failed to process.
            return settings.maskToken();
        }
    }

    public PolicyRegistry registry() {
        return registry;
    }

    public RedactionEngine engine() {
        return engine;
    }

    public RedactionSettings settings() {
        return settings;
    }

    private String applyToSingleValue(Object value, FieldPolicy policy) {
        if (value == null) {
            return null;
        }
        if (policy.isDrop()) {
            return settings.maskToken();
        }
        String redacted = engine.redact(value, policy);
        return redacted != null ? redacted : engine.truncate(String.valueOf(value));
    }

    private String clip(String json, int maxLength) {
        if (maxLength <= 0 || json.length() <= maxLength) {
            return json;
        }
        return json.substring(0, maxLength) + "…(truncated, " + json.length() + " chars)";
    }

    /**
     * The placeholder carries the failure type and the object's class only. The failure <em>message</em>
     * is withheld on purpose: Jackson likes to quote offending values, which is exactly what must not
     * reach the log.
     */
    private String failurePlaceholder(Object value, Throwable failure) {
        String type = value.getClass().getName();
        log.debug("x-log-policy could not render {} safely: {}", type, failure.getClass().getName());
        return "{\"_redactionError\":\"" + failure.getClass().getSimpleName() + "\",\"_type\":\"" + type + "\"}";
    }
}
