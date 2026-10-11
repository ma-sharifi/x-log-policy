package io.xlogpolicy.spring;

import io.xlogpolicy.avro.AvroLogRedactor;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.JacksonLogRedactor;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.core.policy.OverridePolicyResolver;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Makes the {@link LogRedactor} Avro-aware when {@code x-log-policy-avro} is on the classpath.
 *
 * <p>Avro records are rendered from the {@code x-log-policy} declarations in their own schema; everything
 * else goes to the usual Jackson redactor, so one bean serves REST payloads and Kafka events alike. The
 * same instance backs the redacted {@code toString()} of generated records, so they honour the
 * application's configuration (HMAC secret, overrides, limits) too.
 *
 * <p>Ordered before {@link XLogPolicyAutoConfiguration} so that its {@code LogRedactor} steps aside.
 */
@AutoConfiguration(before = XLogPolicyAutoConfiguration.class)
@ConditionalOnClass({AvroLogRedactor.class, org.apache.avro.Schema.class})
@ConditionalOnProperty(prefix = "x-log-policy", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties(XLogPolicyProperties.class)
public class XLogPolicyAvroAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    LogRedactor logRedactor(XLogPolicyProperties properties, PolicyRegistry registry, RedactionEngine engine) {
        JacksonLogRedactor jackson = new JacksonLogRedactor(registry, engine);
        AvroLogRedactor redactor = new AvroLogRedactor(jackson, engine,
                new OverridePolicyResolver(properties.getOverrides()),
                FieldPolicy.of(properties.getDefaultPolicy()));
        LogPolicyStaticHolder.set(redactor);
        AvroLogRedactor.install(redactor);
        return redactor;
    }
}
