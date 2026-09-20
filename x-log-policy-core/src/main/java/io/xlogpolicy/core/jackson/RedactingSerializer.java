package io.xlogpolicy.core.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Map;

/**
 * Writes a property through its policy. Scalars become a single redacted string; collections, arrays and
 * maps have the same policy applied to every element, so a {@code List<String>} of card numbers cannot
 * slip through because it happened to be wrapped in a list.
 */
final class RedactingSerializer extends JsonSerializer<Object> {

    private final RedactionEngine engine;
    private final FieldPolicy policy;

    RedactingSerializer(RedactionEngine engine, FieldPolicy policy) {
        this.engine = engine;
        this.policy = policy;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        if (value == null) {
            gen.writeNull();
            return;
        }
        if (value instanceof Collection<?> collection) {
            writeElements(collection.size(), collection, gen);
        } else if (value.getClass().isArray() && value.getClass() != byte[].class) {
            writeArray(value, gen);
        } else if (value instanceof Map<?, ?> map) {
            gen.writeStartObject();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                gen.writeFieldName(String.valueOf(entry.getKey()));
                serialize(entry.getValue(), gen, provider);
            }
            gen.writeEndObject();
        } else {
            gen.writeString(engine.redact(value, policy));
        }
    }

    /**
     * Type information is deliberately dropped: the output is a redacted placeholder, so emitting a
     * polymorphic type wrapper around it would only add noise (and could leak the concrete type).
     */
    @Override
    public void serializeWithType(Object value, JsonGenerator gen, SerializerProvider provider,
                                  TypeSerializer typeSerializer) throws IOException {
        serialize(value, gen, provider);
    }

    private void writeElements(int size, Iterable<?> elements, JsonGenerator gen) throws IOException {
        int limit = engine.settings().maxCollectionSize();
        gen.writeStartArray();
        int written = 0;
        for (Object element : elements) {
            if (limit > 0 && written == limit) {
                gen.writeString("…(" + (size - written) + " more elements)");
                break;
            }
            if (element == null) {
                gen.writeNull();
            } else {
                gen.writeString(engine.redact(element, policy));
            }
            written++;
        }
        gen.writeEndArray();
    }

    private void writeArray(Object array, JsonGenerator gen) throws IOException {
        int length = Array.getLength(array);
        int limit = engine.settings().maxCollectionSize();
        gen.writeStartArray();
        for (int i = 0; i < length; i++) {
            if (limit > 0 && i == limit) {
                gen.writeString("…(" + (length - i) + " more elements)");
                break;
            }
            Object element = Array.get(array, i);
            if (element == null) {
                gen.writeNull();
            } else {
                gen.writeString(engine.redact(element, policy));
            }
        }
        gen.writeEndArray();
    }
}
