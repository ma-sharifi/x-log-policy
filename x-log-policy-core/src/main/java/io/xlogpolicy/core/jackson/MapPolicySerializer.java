package io.xlogpolicy.core.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

/**
 * Serializes a map whose entries carry no declared policy: each key is looked up by name in the
 * registry, so {@code Map<String, Object>} payloads obey the same contract as typed fields, and unknown
 * keys fall back to the default policy.
 */
final class MapPolicySerializer extends JsonSerializer<Object> {

    private final PolicyRegistry registry;
    private final RedactionEngine engine;
    private final FieldPolicy fallback;

    /**
     * @param fallback policy for keys nothing declares, or {@code null} to use the registry default.
     *                 A map whose property is explicitly {@code SAFE} passes {@code SAFE} here, so the
     *                 operator's intent is honoured while keys that <em>are</em> policied stay redacted.
     */
    MapPolicySerializer(PolicyRegistry registry, RedactionEngine engine, FieldPolicy fallback) {
        this.registry = registry;
        this.engine = engine;
        this.fallback = fallback;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        if (!(value instanceof Map<?, ?> map)) {
            provider.defaultSerializeValue(value, gen);
            return;
        }
        int limit = engine.settings().maxCollectionSize();
        gen.writeStartObject();
        int written = 0;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String key = String.valueOf(entry.getKey());
            Optional<FieldPolicy> declared = registry.resolveExplicitByFieldName(key);
            // A key holding another object or list, with no policy of its own, is descended into so its
            // own keys keep their own policies — the same rule beans follow. Applying the default here
            // would blank out a whole nested object because nothing can declare a policy for a container.
            boolean descend = declared.isEmpty() && isStructured(entry.getValue());
            FieldPolicy policy = descend
                    ? FieldPolicy.of(PolicyType.SAFE)
                    : declared.orElse(fallback == null ? registry.defaultPolicy() : fallback);
            if (policy.isDrop()) {
                continue;
            }
            if (limit > 0 && written == limit) {
                gen.writeFieldName("…");
                gen.writeString("(" + (map.size() - written) + " more entries)");
                break;
            }
            gen.writeFieldName(key);
            writeValue(entry.getValue(), policy, gen, provider);
            written++;
        }
        gen.writeEndObject();
    }

    @Override
    public void serializeWithType(Object value, JsonGenerator gen, SerializerProvider provider,
                                  TypeSerializer typeSerializer) throws IOException {
        serialize(value, gen, provider);
    }

    /** A map or a collection of maps: something whose own keys can still be resolved. */
    private static boolean isStructured(Object value) {
        if (value instanceof Map<?, ?>) {
            return true;
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream().anyMatch(element -> element instanceof Map<?, ?>);
        }
        return false;
    }

    private void writeValue(Object value, FieldPolicy policy, JsonGenerator gen, SerializerProvider provider)
            throws IOException {
        if (value == null) {
            gen.writeNull();
            return;
        }
        if (policy.isSafe()) {
            if (value instanceof Map<?, ?>) {
                // Nested free-form object: keep resolving by key name instead of handing it to Jackson.
                serialize(value, gen, provider);
            } else if (value instanceof Collection<?> collection) {
                gen.writeStartArray();
                for (Object element : collection) {
                    writeValue(element, policy, gen, provider);
                }
                gen.writeEndArray();
            } else if (value instanceof CharSequence text) {
                gen.writeString(engine.truncate(text.toString()));
            } else {
                // Beans go through the provider so their own @LogPolicy fields still apply.
                provider.defaultSerializeValue(value, gen);
            }
            return;
        }
        if (value instanceof Map<?, ?> nested) {
            gen.writeStartObject();
            for (Map.Entry<?, ?> entry : nested.entrySet()) {
                gen.writeFieldName(String.valueOf(entry.getKey()));
                writeValue(entry.getValue(), policy, gen, provider);
            }
            gen.writeEndObject();
        } else if (value instanceof Collection<?> collection) {
            gen.writeStartArray();
            for (Object element : collection) {
                writeValue(element, policy, gen, provider);
            }
            gen.writeEndArray();
        } else {
            gen.writeString(engine.redact(value, policy));
        }
    }
}
