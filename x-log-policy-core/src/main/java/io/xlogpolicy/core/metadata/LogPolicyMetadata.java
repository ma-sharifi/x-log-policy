package io.xlogpolicy.core.metadata;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The policy registry produced at build time from the OpenAPI document(s) and read back at runtime
 * from {@code META-INF/x-log-policy.json}.
 *
 * <p>Two indexes are kept:
 * <ul>
 *   <li>{@code schemas} — {@code schemaName -> propertyName -> policy}, the precise index used when a
 *       Java type can be matched to a schema;</li>
 *   <li>{@code byFieldName} — {@code propertyName -> policy}, the fallback used for map keys, for
 *       free-form JSON text and for types that cannot be matched to a schema. When the same property
 *       name carries different policies in different schemas, the strictest one wins.</li>
 * </ul>
 *
 * <p>This class is the single definition of the on-disk format: the Maven plugin writes it, the
 * starter reads it, so the two cannot drift apart.
 */
public final class LogPolicyMetadata {

    /** Classpath location written by the Maven plugin and read by the starter. */
    public static final String RESOURCE_PATH = "META-INF/x-log-policy.json";

    /** Format version of the JSON document. */
    public static final int FORMAT_VERSION = 1;

    private static final LogPolicyMetadata EMPTY = new LogPolicyMetadata(Map.of(), Map.of());

    private final Map<String, Map<String, FieldPolicy>> schemas;
    private final Map<String, FieldPolicy> byFieldName;

    LogPolicyMetadata(Map<String, Map<String, FieldPolicy>> schemas, Map<String, FieldPolicy> byFieldName) {
        Map<String, Map<String, FieldPolicy>> copy = new LinkedHashMap<>();
        schemas.forEach((schema, properties) -> copy.put(schema, Map.copyOf(properties)));
        this.schemas = Map.copyOf(copy);
        this.byFieldName = Map.copyOf(byFieldName);
    }

    public static LogPolicyMetadata empty() {
        return EMPTY;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Looks up {@code schemaName.propertyName}. */
    public Optional<FieldPolicy> find(String schemaName, String propertyName) {
        Map<String, FieldPolicy> properties = schemas.get(schemaName);
        return properties == null ? Optional.empty() : Optional.ofNullable(properties.get(propertyName));
    }

    /** Looks up a property name across all schemas. */
    public Optional<FieldPolicy> findByFieldName(String propertyName) {
        return Optional.ofNullable(byFieldName.get(propertyName));
    }

    public Map<String, Map<String, FieldPolicy>> schemas() {
        return schemas;
    }

    public Map<String, FieldPolicy> byFieldName() {
        return byFieldName;
    }

    public boolean isEmpty() {
        return schemas.isEmpty() && byFieldName.isEmpty();
    }

    /** Merges two registries, e.g. when several specs (or several jars) contribute policies. */
    public LogPolicyMetadata merge(LogPolicyMetadata other) {
        if (other.isEmpty()) {
            return this;
        }
        Builder builder = builder();
        schemas.forEach((schema, props) -> props.forEach((name, policy) -> builder.add(schema, name, policy)));
        other.schemas.forEach((schema, props) -> props.forEach((name, policy) -> builder.add(schema, name, policy)));
        return builder.build();
    }

    /**
     * Relative strictness of a policy, used to resolve {@code byFieldName} collisions.
     * Higher means less is revealed.
     */
    public static int strictness(PolicyType type) {
        return switch (type) {
            case SAFE -> 0;
            case PARTIAL -> 1;
            case HASH -> 2;
            case TOKENIZE -> 3;
            case HMAC -> 4;
            case CUSTOM -> 5;
            case MASK -> 6;
            case DROP -> 7;
        };
    }

    /** Accumulates policies and maintains the {@code byFieldName} index. */
    public static final class Builder {

        private final Map<String, Map<String, FieldPolicy>> schemas = new TreeMap<>();
        private final Map<String, FieldPolicy> byFieldName = new TreeMap<>();

        public Builder add(String schemaName, String propertyName, FieldPolicy policy) {
            schemas.computeIfAbsent(schemaName, key -> new TreeMap<>()).put(propertyName, policy);
            byFieldName.merge(propertyName, policy, (existing, candidate) ->
                    strictness(candidate.type()) > strictness(existing.type()) ? candidate : existing);
            return this;
        }

        public boolean isEmpty() {
            return schemas.isEmpty();
        }

        public LogPolicyMetadata build() {
            return new LogPolicyMetadata(schemas, byFieldName);
        }
    }
}
