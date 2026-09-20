package io.xlogpolicy.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.JacksonLogRedactor;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.metadata.PolicyMetadataIO;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;
import io.xlogpolicy.core.redaction.Tokenizer;
import io.xlogpolicy.core.redaction.ValueRedaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.List;

/**
 * Wires the redactor from the build-time registry and the application's configuration.
 *
 * <p>Every bean is conditional on being missing, so an application can replace any part: the whole
 * {@link LogRedactor}, the {@link PolicyRegistry}, a single {@link ValueRedaction} (registering one named
 * after a built-in replaces that built-in), or the {@link Tokenizer}.
 */
@AutoConfiguration
@ConditionalOnClass(ObjectMapper.class)
@ConditionalOnProperty(prefix = "x-log-policy", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties(XLogPolicyProperties.class)
public class XLogPolicyAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(XLogPolicyAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    LogPolicyMetadata xLogPolicyMetadata(XLogPolicyProperties properties) {
        if (!properties.isLoadMetadata()) {
            return LogPolicyMetadata.empty();
        }
        List<String> problems = new ArrayList<>();
        LogPolicyMetadata metadata = PolicyMetadataIO.loadAll(
                XLogPolicyAutoConfiguration.class.getClassLoader(), problems);
        problems.forEach(problem -> log.warn("x-log-policy: could not read a policy registry: {}", problem));

        if (metadata.isEmpty()) {
            log.info("x-log-policy: no {} on the classpath; policies come from @LogPolicy and configuration"
                            + " only, and everything else is {}",
                    LogPolicyMetadata.RESOURCE_PATH, properties.getDefaultPolicy());
        } else {
            log.info("x-log-policy: loaded {} schema(s) covering {} distinct field name(s); default policy {}",
                    metadata.schemas().size(), metadata.byFieldName().size(), properties.getDefaultPolicy());
        }
        return metadata;
    }

    @Bean
    @ConditionalOnMissingBean
    RedactionSettings xLogPolicyRedactionSettings(XLogPolicyProperties properties, LogPolicyMetadata metadata) {
        boolean needsKey = properties.getDefaultPolicy() == PolicyType.HMAC
                || properties.getDefaultPolicy() == PolicyType.TOKENIZE
                || metadata.byFieldName().values().stream()
                        .anyMatch(policy -> policy.type() == PolicyType.HMAC || policy.type() == PolicyType.TOKENIZE)
                || properties.getOverrides().values().stream()
                        .anyMatch(value -> value != null
                                && (value.toUpperCase(java.util.Locale.ROOT).startsWith("HMAC")
                                || value.toUpperCase(java.util.Locale.ROOT).startsWith("TOKEN")));
        String secret = properties.getHmac().getSecret();
        if (needsKey && (secret == null || secret.isBlank())) {
            log.warn("x-log-policy: a keyed policy (HMAC/TOKENIZE) is in use but x-log-policy.hmac.secret is"
                    + " not set. A random key is generated for this JVM, so digests will not match across"
                    + " restarts or instances. Set the secret from the environment to correlate values.");
        }
        return properties.toRedactionSettings();
    }

    @Bean
    @ConditionalOnMissingBean
    PolicyRegistry xLogPolicyRegistry(XLogPolicyProperties properties, LogPolicyMetadata metadata) {
        return PolicyRegistry.standard(properties.getOverrides(), metadata,
                FieldPolicy.of(properties.getDefaultPolicy()));
    }

    @Bean
    @ConditionalOnMissingBean
    RedactionEngine xLogPolicyRedactionEngine(RedactionSettings settings,
                                             ObjectProvider<Tokenizer> tokenizer,
                                             ObjectProvider<ValueRedaction> redactions) {
        List<ValueRedaction> additional = redactions.orderedStream().toList();
        if (!additional.isEmpty()) {
            log.debug("x-log-policy: {} application redaction(s) registered: {}", additional.size(),
                    additional.stream().map(ValueRedaction::name).toList());
        }
        return new RedactionEngine(settings, tokenizer.getIfAvailable(), additional);
    }

    @Bean
    @ConditionalOnMissingBean
    LogRedactor logRedactor(PolicyRegistry registry, RedactionEngine engine) {
        JacksonLogRedactor redactor = new JacksonLogRedactor(registry, engine);
        // Makes the same redactor available to log framework converters, which the container does not build.
        LogPolicyStaticHolder.set(redactor);
        return redactor;
    }
}
