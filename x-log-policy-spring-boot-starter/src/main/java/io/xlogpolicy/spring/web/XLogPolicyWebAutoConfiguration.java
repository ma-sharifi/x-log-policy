package io.xlogpolicy.spring.web;

import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.spring.XLogPolicyAutoConfiguration;
import io.xlogpolicy.spring.XLogPolicyProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Registers the HTTP payload logging filter when the application opts in with
 * {@code x-log-policy.http.enabled=true}.
 *
 * <p>Off by default on purpose: switching on request logging changes what a service writes to disk, and
 * that is the operator's decision, not a library's.
 */
@AutoConfiguration(after = XLogPolicyAutoConfiguration.class)
@ConditionalOnClass({OncePerRequestFilter.class, jakarta.servlet.Filter.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "x-log-policy.http", name = "enabled", havingValue = "true")
@ConditionalOnBean(LogRedactor.class)
public class XLogPolicyWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    FilterRegistrationBean<LogPolicyLoggingFilter> xLogPolicyLoggingFilter(LogRedactor redactor,
                                                                          XLogPolicyProperties properties) {
        FilterRegistrationBean<LogPolicyLoggingFilter> registration = new FilterRegistrationBean<>(
                new LogPolicyLoggingFilter(redactor, properties.getHttp()));
        registration.setName("xLogPolicyLoggingFilter");
        // Late enough that the request is fully resolved, early enough to see the real status.
        registration.setOrder(Ordered.LOWEST_PRECEDENCE - 100);
        return registration;
    }
}
