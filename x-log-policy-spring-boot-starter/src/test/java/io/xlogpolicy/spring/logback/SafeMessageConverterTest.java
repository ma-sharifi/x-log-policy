package io.xlogpolicy.spring.logback;

import ch.qos.logback.classic.spi.LoggingEvent;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.spring.LogPolicyStaticHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SafeMessageConverterTest {

    private final SafeMessageConverter converter = new SafeMessageConverter();

    @AfterEach
    void clearHolder() {
        LogPolicyStaticHolder.reset();
    }

    @Test
    void a_declared_field_is_redacted_inside_a_formatted_message() {
        // No Spring context here: the holder bootstraps from META-INF/x-log-policy.json on the classpath,
        // which is exactly the situation a Logback converter runs in.
        assertThat(converter.convert(event("stored {}", "{\"id\":\"c-1\",\"ssn\":\"123-45-6789\"}")))
                .isEqualTo("stored {\"id\":\"c-1\",\"ssn\":\"***\"}");
    }

    @Test
    void an_unrelated_message_is_left_exactly_as_it_was() {
        assertThat(converter.convert(event("started in {}ms", 412))).isEqualTo("started in 412ms");
    }

    @Test
    void the_configured_redactor_is_used_once_the_context_is_up() {
        LogPolicyStaticHolder.set(new StubRedactor());
        assertThat(converter.convert(event("anything {}", "at all"))).isEqualTo("from-the-context");
    }

    @Test
    void a_failing_redactor_masks_rather_than_breaking_the_appender() {
        LogPolicyStaticHolder.set(new StubRedactor() {
            @Override
            public String redactText(String text) {
                throw new IllegalStateException("boom");
            }
        });
        assertThat(converter.convert(event("payload {}", "sensitive"))).isEqualTo("***");
    }

    @Test
    void an_empty_message_is_passed_through() {
        assertThat(converter.convert(event(""))).isEmpty();
    }

    private static LoggingEvent event(String message, Object... arguments) {
        LoggingEvent event = new LoggingEvent();
        event.setMessage(message);
        event.setArgumentArray(arguments);
        return event;
    }

    private static class StubRedactor implements LogRedactor {
        @Override
        public String toSafeJson(Object value) {
            return "from-the-context";
        }

        @Override
        public String toSafeJson(Object value, int maxLength) {
            return "from-the-context";
        }

        @Override
        public String redactValue(Class<?> owner, String property, Object value) {
            return "from-the-context";
        }

        @Override
        public String redactValue(String property, Object value) {
            return "from-the-context";
        }

        @Override
        public String redactText(String text) {
            return "from-the-context";
        }
    }
}
