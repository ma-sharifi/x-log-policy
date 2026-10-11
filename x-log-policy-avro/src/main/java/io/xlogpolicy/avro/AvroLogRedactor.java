package io.xlogpolicy.avro;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.JacksonLogRedactor;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import io.xlogpolicy.core.policy.OverridePolicyResolver;
import io.xlogpolicy.core.redaction.RedactionEngine;
import org.apache.avro.Schema;
import org.apache.avro.generic.GenericEnumSymbol;
import org.apache.avro.generic.GenericFixed;
import org.apache.avro.generic.IndexedRecord;
import org.apache.avro.specific.SpecificData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link LogRedactor} for Avro records — generated {@code SpecificRecord}s and {@code GenericRecord}s
 * alike — driven by the {@code x-log-policy} declarations in the record's own schema.
 *
 * <p>Anything that is not an Avro record is handed to a delegate, so one instance serves an application
 * that logs both REST payloads and Kafka events.
 *
 * <p>Precedence, highest first: a configuration override ({@code Schema.field}, {@code *.field}), the
 * field's policy, the record's default, and finally the default policy — {@code MASK} unless configured
 * otherwise. A nested record with no policy of its own is descended into, so its fields keep theirs.
 *
 * <p>The same safety properties as {@link JacksonLogRedactor}: nothing is thrown, and depth, string
 * length, collection size and total length are bounded.
 */
public final class AvroLogRedactor implements LogRedactor {

    private static final Logger log = LoggerFactory.getLogger(AvroLogRedactor.class);
    private static final JsonFactory JSON = new JsonFactory();

    private static volatile AvroLogRedactor shared;

    private final LogRedactor delegate;
    private final RedactionEngine engine;
    private final RedactionSettings settings;
    private final OverridePolicyResolver overrides;
    private final FieldPolicy defaultPolicy;
    private final ConcurrentHashMap<Schema, FieldPolicy[]> policiesBySchema = new ConcurrentHashMap<>();

    /**
     * @param delegate      renders everything that is not an Avro record
     * @param engine        applies the policies
     * @param overrides     configuration overrides, highest precedence
     * @param defaultPolicy for values nothing declares; {@code MASK} keeps it fail-closed
     */
    public AvroLogRedactor(LogRedactor delegate, RedactionEngine engine, OverridePolicyResolver overrides,
                           FieldPolicy defaultPolicy) {
        this.delegate = delegate;
        this.engine = engine;
        this.settings = engine.settings();
        this.overrides = overrides == null ? OverridePolicyResolver.none() : overrides;
        this.defaultPolicy = defaultPolicy == null ? FieldPolicy.of(PolicyType.MASK) : defaultPolicy;
    }

    /** A fail-closed redactor with default settings and no overrides. */
    public static AvroLogRedactor withDefaults() {
        return new AvroLogRedactor(JacksonLogRedactor.withDefaults(), RedactionEngine.withDefaults(),
                OverridePolicyResolver.none(), FieldPolicy.of(PolicyType.MASK));
    }

    /**
     * Installs the redactor used by {@link #toSafeString(IndexedRecord)}. The Spring Boot starter calls
     * this with the configured instance; a plain Java application should call it once at startup, or
     * keyed policies get a random per-JVM key.
     */
    public static void install(AvroLogRedactor redactor) {
        shared = redactor;
    }

    /** @return the installed redactor, or a default one when none was installed */
    public static AvroLogRedactor shared() {
        AvroLogRedactor current = shared;
        if (current == null) {
            synchronized (AvroLogRedactor.class) {
                current = shared;
                if (current == null) {
                    current = withDefaults();
                    shared = current;
                }
            }
        }
        return current;
    }

    /**
     * What a generated record's {@code toString()} returns once {@code x-log-policy-maven-plugin} has
     * rewritten it, so that {@code log.info("{}", event)} — and every library that logs a record — is safe.
     */
    public static String toSafeString(IndexedRecord record) {
        return shared().toSafeJson(record);
    }

    @Override
    public String toSafeJson(Object value) {
        return toSafeJson(value, settings.maxJsonLength());
    }

    @Override
    public String toSafeJson(Object value, int maxLength) {
        if (!(value instanceof IndexedRecord record)) {
            return delegate.toSafeJson(value, maxLength);
        }
        try {
            StringWriter out = new StringWriter();
            try (JsonGenerator gen = JSON.createGenerator(out)) {
                if (settings.prettyPrint()) {
                    gen.useDefaultPrettyPrinter();
                }
                writeRecord(record, gen, 1);
            }
            return clip(out.toString(), maxLength);
        } catch (Exception | StackOverflowError failure) {
            return failurePlaceholder(record, failure);
        }
    }

    @Override
    public String redactValue(Class<?> owner, String property, Object value) {
        Optional<Schema> schema = schemaOf(owner);
        Schema.Field field = schema.map(record -> record.getField(property)).orElse(null);
        if (field == null) {
            return delegate.redactValue(owner, property, value);
        }
        if (value == null) {
            return null;
        }
        FieldPolicy declared = policiesFor(schema.get())[field.pos()];
        FieldPolicy policy = declared != null ? declared : defaultPolicy;
        if (policy.isDrop()) {
            return settings.maskToken();
        }
        String redacted = engine.redact(normalize(value), policy);
        return redacted != null ? redacted : engine.truncate(String.valueOf(normalize(value)));
    }

    @Override
    public String redactValue(String property, Object value) {
        return delegate.redactValue(property, value);
    }

    @Override
    public String redactText(String text) {
        return delegate.redactText(text);
    }

    public RedactionEngine engine() {
        return engine;
    }

    private void writeRecord(IndexedRecord record, JsonGenerator gen, int depth) throws IOException {
        Schema schema = record.getSchema();
        FieldPolicy[] policies = policiesFor(schema);
        gen.writeStartObject();
        for (Schema.Field field : schema.getFields()) {
            Object value = record.get(field.pos());
            FieldPolicy policy = policies[field.pos()];
            if (policy == null && isLeaf(value)) {
                policy = defaultPolicy;
            }
            if (policy != null && policy.isDrop()) {
                continue;
            }
            gen.writeFieldName(field.name());
            writeValue(value, policy, gen, depth + 1);
        }
        gen.writeEndObject();
    }

    /**
     * @param policy the policy in force, {@code null} when nothing declares one — a record is then
     *               descended into and a leaf gets the default policy
     */
    private void writeValue(Object value, FieldPolicy policy, JsonGenerator gen, int depth) throws IOException {
        if (value == null) {
            gen.writeNull();
            return;
        }
        if (!isLeaf(value) && depth > settings.maxDepth()) {
            gen.writeString("…(max depth " + settings.maxDepth() + ")");
            return;
        }
        if (value instanceof IndexedRecord nested) {
            if (policy == null || policy.isSafe()) {
                writeRecord(nested, gen, depth);
            } else {
                writeLeaf(nested, policy, gen);
            }
        } else if (value instanceof Map<?, ?> map) {
            // A policy on a map applies to its values; the keys are written as they are, like any JSON key.
            gen.writeStartObject();
            int written = 0;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (reachedLimit(written++, map.size(), gen, true)) {
                    break;
                }
                gen.writeFieldName(String.valueOf(entry.getKey()));
                writeValue(entry.getValue(), policy, gen, depth + 1);
            }
            gen.writeEndObject();
        } else if (value instanceof Collection<?> collection) {
            gen.writeStartArray();
            int written = 0;
            for (Object element : collection) {
                if (reachedLimit(written++, collection.size(), gen, false)) {
                    break;
                }
                writeValue(element, policy, gen, depth + 1);
            }
            gen.writeEndArray();
        } else {
            writeLeaf(value, policy != null ? policy : defaultPolicy, gen);
        }
    }

    private boolean reachedLimit(int written, int size, JsonGenerator gen, boolean inObject) throws IOException {
        int limit = settings.maxCollectionSize();
        if (limit <= 0 || written < limit) {
            return false;
        }
        if (inObject) {
            gen.writeFieldName("…");
        }
        gen.writeString("…(" + (size - written) + " more elements)");
        return true;
    }

    private void writeLeaf(Object value, FieldPolicy policy, JsonGenerator gen) throws IOException {
        if (policy.isDrop()) {
            // Only reachable for an element of a collection: the collection itself cannot omit it.
            gen.writeString(settings.maskToken());
            return;
        }
        Object normalized = normalize(value);
        if (!policy.isSafe()) {
            gen.writeString(engine.redact(normalized, policy));
        } else if (normalized instanceof Integer || normalized instanceof Long) {
            gen.writeNumber(((Number) normalized).longValue());
        } else if (normalized instanceof Float || normalized instanceof Double) {
            gen.writeNumber(((Number) normalized).doubleValue());
        } else if (normalized instanceof BigDecimal decimal) {
            gen.writeNumber(decimal);
        } else if (normalized instanceof BigInteger integer) {
            gen.writeNumber(integer);
        } else if (normalized instanceof Boolean bool) {
            gen.writeBoolean(bool);
        } else {
            gen.writeString(engine.truncate(String.valueOf(normalized)));
        }
    }

    /** Avro's own representations, turned into the text a redaction (or a reader) expects. */
    private static Object normalize(Object value) {
        if (value instanceof CharSequence text) {
            return text.toString();
        }
        if (value instanceof ByteBuffer buffer) {
            ByteBuffer copy = buffer.duplicate();
            byte[] bytes = new byte[copy.remaining()];
            copy.get(bytes);
            return Base64.getEncoder().encodeToString(bytes);
        }
        if (value instanceof GenericFixed fixed) {
            return Base64.getEncoder().encodeToString(fixed.bytes());
        }
        if (value instanceof GenericEnumSymbol<?> symbol) {
            return symbol.toString();
        }
        return value;
    }

    private static boolean isLeaf(Object value) {
        return !(value instanceof IndexedRecord || value instanceof Map || value instanceof Collection);
    }

    /** One entry per field position; {@code null} where nothing declares a policy. */
    private FieldPolicy[] policiesFor(Schema schema) {
        return policiesBySchema.computeIfAbsent(schema, this::resolvePolicies);
    }

    private FieldPolicy[] resolvePolicies(Schema schema) {
        FieldPolicy recordDefault = parseOrMask(schema.getFullName(), () -> AvroPolicies.recordDefault(schema));
        FieldPolicy[] policies = new FieldPolicy[schema.getFields().size()];
        for (Schema.Field field : schema.getFields()) {
            FieldPolicy policy = overrides.resolve(schema.getFullName(), schema.getName(), field.name())
                    .orElseGet(() -> parseOrMask(schema.getFullName() + "." + field.name(),
                            () -> AvroPolicies.declared(field)));
            policies[field.pos()] = policy != null ? policy : recordDefault;
        }
        return policies;
    }

    /** A malformed declaration must not fall through to the raw value: it is masked, and reported once. */
    private FieldPolicy parseOrMask(String where, java.util.function.Supplier<Optional<FieldPolicy>> parse) {
        try {
            return parse.get().orElse(null);
        } catch (RuntimeException ex) {
            log.warn("x-log-policy: invalid declaration on {} ({}); masking it", where, ex.getMessage());
            return FieldPolicy.of(PolicyType.MASK);
        }
    }

    private static Optional<Schema> schemaOf(Class<?> owner) {
        if (owner == null || !IndexedRecord.class.isAssignableFrom(owner)) {
            return Optional.empty();
        }
        try {
            Schema schema = SpecificData.get().getSchema(owner);
            return schema.getType() == Schema.Type.RECORD ? Optional.of(schema) : Optional.empty();
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    private String clip(String json, int maxLength) {
        if (maxLength <= 0 || json.length() <= maxLength) {
            return json;
        }
        return json.substring(0, maxLength) + "…(truncated, " + json.length() + " chars)";
    }

    /** As in {@link JacksonLogRedactor}: the failure type and the record name only, never a message. */
    private String failurePlaceholder(IndexedRecord record, Throwable failure) {
        String type;
        try {
            type = record.getSchema().getFullName();
        } catch (RuntimeException ex) {
            type = record.getClass().getName();
        }
        log.debug("x-log-policy could not render {} safely: {}", type, failure.getClass().getName());
        return "{\"_redactionError\":\"" + failure.getClass().getSimpleName() + "\",\"_type\":\"" + type + "\"}";
    }
}
