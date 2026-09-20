package io.xlogpolicy.spring.log4j2;

import io.xlogpolicy.spring.LogPolicyStaticHolder;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.pattern.ConverterKeys;
import org.apache.logging.log4j.core.pattern.LogEventPatternConverter;
import org.apache.logging.log4j.core.pattern.PatternConverter;

/**
 * Log4j2 counterpart of {@link io.xlogpolicy.spring.logback.SafeMessageConverter}. Use {@code %safeMsg}
 * in the pattern layout:
 *
 * <pre>{@code
 * <PatternLayout pattern="%d{HH:mm:ss.SSS} %-5level %logger{36} - %safeMsg%n"/>
 * }</pre>
 *
 * <p>The same caveat applies: only explicitly declared policies are applied.
 */
@Plugin(name = "SafeMessagePatternConverter", category = PatternConverter.CATEGORY)
@ConverterKeys({"safeMsg", "safeMessage"})
public final class SafeMessagePatternConverter extends LogEventPatternConverter {

    private SafeMessagePatternConverter() {
        super("SafeMessage", "safeMsg");
    }

    @SuppressWarnings("unused") // Called reflectively by Log4j2.
    public static SafeMessagePatternConverter newInstance(String[] options) {
        return new SafeMessagePatternConverter();
    }

    @Override
    public void format(LogEvent event, StringBuilder toAppendTo) {
        String message = event.getMessage() == null ? null : event.getMessage().getFormattedMessage();
        if (message == null || message.isEmpty()) {
            return;
        }
        try {
            toAppendTo.append(LogPolicyStaticHolder.get().redactText(message));
        } catch (RuntimeException | StackOverflowError failure) {
            toAppendTo.append("***");
        }
    }
}
