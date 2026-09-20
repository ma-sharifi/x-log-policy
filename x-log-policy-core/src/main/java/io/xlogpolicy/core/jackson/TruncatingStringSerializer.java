package io.xlogpolicy.core.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.io.IOException;

/**
 * Keeps a safe-but-long text field from filling the log line. Applied only to {@code SAFE} text
 * properties; redacted values are already short.
 */
final class TruncatingStringSerializer extends JsonSerializer<Object> {

    private final RedactionEngine engine;

    TruncatingStringSerializer(RedactionEngine engine) {
        this.engine = engine;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        if (value == null) {
            gen.writeNull();
        } else {
            gen.writeString(engine.truncate(value.toString()));
        }
    }
}
