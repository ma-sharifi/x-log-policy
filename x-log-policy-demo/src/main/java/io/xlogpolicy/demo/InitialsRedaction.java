package io.xlogpolicy.demo;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.redaction.ValueRedaction;
import org.springframework.stereotype.Component;

/**
 * The application's own redaction, referenced from the spec as
 * {@code x-log-policy: {policy: CUSTOM, name: initials}}.
 *
 * <p>Registering it as a bean is all that is needed; the starter picks up every
 * {@link ValueRedaction} on the context.
 *
 * <p>It is deliberately idempotent. The {@code %safeMsg} converter in {@code logback-spring.xml} may see
 * a message that already went through the redactor, and applying initials to "A.L." a second time would
 * give "A." — so already-reduced input is returned untouched. Built-in policies are recognised by the
 * text redactor itself; a custom one has to take care of it.
 */
@Component
public class InitialsRedaction implements ValueRedaction {

    @Override
    public String name() {
        return "initials";
    }

    private static final java.util.regex.Pattern ALREADY_INITIALS =
            java.util.regex.Pattern.compile("(?:\\p{Lu}\\.)+");

    @Override
    public String redact(Object value, FieldPolicy policy) {
        String text = String.valueOf(value).trim();
        if (ALREADY_INITIALS.matcher(text).matches()) {
            return text;
        }
        StringBuilder initials = new StringBuilder();
        for (String part : text.split("\\s+")) {
            if (!part.isEmpty()) {
                initials.append(Character.toUpperCase(part.charAt(0))).append('.');
            }
        }
        return initials.isEmpty() ? "***" : initials.toString();
    }
}
