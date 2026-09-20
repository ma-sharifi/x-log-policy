package io.xlogpolicy.spring.logback;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import io.xlogpolicy.spring.LogPolicyStaticHolder;

/**
 * Logback pattern converter that redacts declared fields inside an already formatted message — the last
 * line of defence for code that logs an object or a JSON string directly instead of going through
 * {@link io.xlogpolicy.core.LogRedactor}.
 *
 * <p>Register it in {@code logback-spring.xml} and use {@code %safeMsg} where {@code %msg} would go:
 *
 * <pre>{@code
 * <conversionRule conversionWord="safeMsg"
 *                 class="io.xlogpolicy.spring.logback.SafeMessageConverter"/>
 * <encoder>
 *   <pattern>%d{HH:mm:ss.SSS} %-5level %logger{36} - %safeMsg%n</pattern>
 * </encoder>
 * }</pre>
 *
 * <p>It applies only policies that are explicitly declared, since masking every JSON-looking key in every
 * log message would destroy unrelated output. Treat it as a net, not as the mechanism.
 */
public class SafeMessageConverter extends ClassicConverter {

    @Override
    public String convert(ILoggingEvent event) {
        String message = event.getFormattedMessage();
        if (message == null || message.isEmpty()) {
            return message;
        }
        try {
            return LogPolicyStaticHolder.get().redactText(message);
        } catch (RuntimeException | StackOverflowError failure) {
            // Never let the appender fail: an unredacted line is worse, so fall back to a mask.
            return "***";
        }
    }
}
