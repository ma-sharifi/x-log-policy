package io.xlogpolicy.avro;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.policy.PolicyParser;
import org.apache.avro.JsonProperties;
import org.apache.avro.Schema;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Reads {@code x-log-policy} out of an Avro schema.
 *
 * <p>Avro keeps any attribute it does not recognise as a schema property, so the declaration travels
 * inside the schema itself: in the {@code SCHEMA$} of every generated class, and in the writer schema of
 * every {@code GenericRecord} a consumer decodes. No separate registry is needed at runtime.
 *
 * <pre>{@code
 * {"type": "record", "name": "Customer", "fields": [
 *   {"name": "id",         "type": "string", "x-log-policy": "SAFE"},
 *   {"name": "cardNumber", "type": "string", "x-log-policy": {"policy": "PARTIAL", "keep": 4}},
 *   {"name": "phones",     "type": {"type": "array", "items": "string", "x-log-policy": "HASH"}},
 *   {"name": "address",    "type": "Address"}
 * ]}
 * }</pre>
 *
 * <p>Where a policy may appear, in the order it is looked for:
 * <ol>
 *   <li>on the field — the common case;</li>
 *   <li>on the field's type: a primitive written in object form, an {@code array} (applies to the
 *       items), a {@code map} (applies to the values), or a branch of a union such as
 *       {@code ["null", ...]};</li>
 *   <li>on the record — the default for every field of that record that declares none.</li>
 * </ol>
 * A field whose type is another record needs no policy: it is descended into.
 */
public final class AvroPolicies {

    private AvroPolicies() {
    }

    /**
     * @return the policy the field declares, on itself or on its type
     * @throws IllegalArgumentException when the declaration is malformed
     */
    public static Optional<FieldPolicy> declared(Schema.Field field) {
        Object raw = rawPolicy(field);
        if (raw != null) {
            return Optional.of(PolicyParser.parse(raw));
        }
        return declaredOnType(field.schema());
    }

    /**
     * @return the default a record declares for its fields
     * @throws IllegalArgumentException when the declaration is malformed
     */
    public static Optional<FieldPolicy> recordDefault(Schema record) {
        Object raw = record.getType() == Schema.Type.RECORD ? rawPolicy(record) : null;
        return raw == null ? Optional.empty() : Optional.of(PolicyParser.parse(raw));
    }

    /**
     * Whether a field of this type holds another record, directly or through a union, array or map. Such
     * a field is descended into rather than redacted as one value, so it needs no policy of its own.
     */
    public static boolean isStructured(Schema schema) {
        return switch (schema.getType()) {
            case RECORD -> true;
            case ARRAY -> isStructured(schema.getElementType());
            case MAP -> isStructured(schema.getValueType());
            case UNION -> schema.getTypes().stream().anyMatch(AvroPolicies::isStructured);
            default -> false;
        };
    }

    private static Optional<FieldPolicy> declaredOnType(Schema schema) {
        switch (schema.getType()) {
            case RECORD:
                // A record's own policy is the default for its fields, not a policy on the field using it.
                return Optional.empty();
            case UNION:
                for (Schema branch : schema.getTypes()) {
                    Optional<FieldPolicy> found = declaredOnType(branch);
                    if (found.isPresent()) {
                        return found;
                    }
                }
                return Optional.empty();
            default:
                break;
        }
        Object raw = rawPolicy(schema);
        if (raw != null) {
            return Optional.of(PolicyParser.parse(raw));
        }
        return switch (schema.getType()) {
            case ARRAY -> declaredOnType(schema.getElementType());
            case MAP -> declaredOnType(schema.getValueType());
            default -> Optional.empty();
        };
    }

    private static Object rawPolicy(JsonProperties properties) {
        for (Map.Entry<String, Object> property : properties.getObjectProps().entrySet()) {
            if (property.getKey().toLowerCase(Locale.ROOT).equals(PolicyParser.EXTENSION)) {
                return property.getValue();
            }
        }
        return null;
    }
}
