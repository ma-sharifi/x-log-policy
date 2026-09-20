package io.xlogpolicy.spring;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.redaction.RedactionEngine;
import io.xlogpolicy.core.redaction.Tokenizer;
import io.xlogpolicy.core.redaction.ValueRedaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class XLogPolicyAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(XLogPolicyAutoConfiguration.class));

    @AfterEach
    void clearStaticHolder() {
        LogPolicyStaticHolder.reset();
    }

    @Test
    void the_redactor_is_available_by_default_and_fails_closed() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(LogRedactor.class);
            assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account()))
                    .contains("\"reference\":\"acc-1\"")
                    .contains("\"iban\":\"***\"")
                    .contains("\"balance\":\"***\"")   // undeclared, so masked
                    .doesNotContain("NL91ABNA0417164300");
        });
    }

    @Test
    void the_default_policy_is_configurable() {
        runner.withPropertyValues("x-log-policy.default-policy=SAFE").run(context ->
                assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account()))
                        .contains("\"balance\":42")
                        .contains("\"iban\":\"***\""));
    }

    @Test
    void the_whole_starter_can_be_switched_off() {
        runner.withPropertyValues("x-log-policy.enabled=false").run(context ->
                assertThat(context).doesNotHaveBean(LogRedactor.class));
    }

    @Test
    void an_application_redactor_replaces_the_default() {
        runner.withUserConfiguration(CustomRedactorConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(LogRedactor.class);
            assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account())).isEqualTo("replaced");
        });
    }

    @Test
    void an_application_value_redaction_is_registered_and_can_replace_a_builtin() {
        runner.withUserConfiguration(CustomRedactionConfiguration.class).run(context -> {
            assertThat(context.getBean(RedactionEngine.class).registeredNames()).contains("initials");
            assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account()))
                    .contains("\"iban\":\"[hidden]\"");   // MASK replaced by the application
        });
    }

    @Test
    void an_application_tokenizer_is_used_for_the_tokenize_policy() {
        runner.withUserConfiguration(CustomTokenizerConfiguration.class)
                .withPropertyValues("x-log-policy.overrides.[Account.reference]=TOKENIZE")
                .run(context -> assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account()))
                        .contains("\"reference\":\"tok-acc-1\""));
    }

    @Test
    void overrides_from_configuration_win_over_annotations() {
        runner.withPropertyValues("x-log-policy.overrides.[Account.iban]=PARTIAL:4").run(context ->
                assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account()))
                        .contains("\"iban\":\"" + "*".repeat(14) + "4300\""));
    }

    @Test
    void settings_are_taken_from_configuration() {
        runner.withPropertyValues(
                "x-log-policy.mask-token=[redacted]",
                "x-log-policy.partial-keep=2",
                "x-log-policy.max-json-length=0",
                "x-log-policy.pretty-print=true").run(context -> {
            RedactionSettings settings = context.getBean(RedactionSettings.class);
            assertThat(settings.maskToken()).isEqualTo("[redacted]");
            assertThat(settings.partialKeep()).isEqualTo(2);
            assertThat(settings.prettyPrint()).isTrue();
            assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account()))
                    .contains("\"iban\" : \"[redacted]\"");
        });
    }

    @Test
    void the_registry_is_loaded_from_the_classpath_and_can_be_disabled() {
        runner.run(context -> assertThat(context.getBean(LogPolicyMetadata.class)
                .find("ThirdPartyPayload", "taxNumber").orElseThrow().type()).isEqualTo(PolicyType.MASK));
        runner.withPropertyValues("x-log-policy.load-metadata=false").run(context ->
                assertThat(context.getBean(LogPolicyMetadata.class).isEmpty()).isTrue());
    }

    @Test
    void the_registry_covers_types_that_carry_no_annotation() {
        // Nothing annotates ThirdPartyPayload; the policies come from META-INF/x-log-policy.json.
        runner.run(context -> assertThat(context.getBean(LogRedactor.class).toSafeJson(new ThirdPartyPayload()))
                .contains("\"customerRef\":\"cust-9\"")
                .contains("\"taxNumber\":\"***\"")
                .doesNotContain("NL123456789B01"));
    }

    @Test
    void a_keyed_policy_without_a_secret_warns_but_still_starts() {
        runner.withPropertyValues("x-log-policy.default-policy=HMAC").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(LogRedactor.class).toSafeJson(new Account())).contains("hmac:");
        });
    }

    @Test
    void a_configured_secret_makes_digests_reproducible() {
        String first = digestWithSecret("a-stable-secret");
        String second = digestWithSecret("a-stable-secret");
        String other = digestWithSecret("a-different-secret");

        assertThat(first).isEqualTo(second).isNotEqualTo(other);
    }

    @Test
    void the_static_holder_is_populated_for_log_framework_converters() {
        runner.run(context -> assertThat(LogPolicyStaticHolder.get()).isSameAs(context.getBean(LogRedactor.class)));
    }

    private String digestWithSecret(String secret) {
        StringBuilder captured = new StringBuilder();
        runner.withPropertyValues("x-log-policy.hmac.secret=" + secret,
                        "x-log-policy.overrides.[Account.reference]=HMAC")
                .run((AssertableApplicationContext context) -> captured.append(context.getBean(LogRedactor.class)
                        .redactValue(Account.class, "reference", "acc-1")));
        return captured.toString();
    }

    /** Annotated fixture: the annotation path does not need the registry. */
    static class Account {
        @LogPolicy(PolicyType.SAFE)
        public String reference = "acc-1";

        @LogPolicy(PolicyType.MASK)
        public String iban = "NL91ABNA0417164300";

        public int balance = 42;
    }

    /** Unannotated fixture: covered only by the test registry on the classpath. */
    static class ThirdPartyPayload {
        public String customerRef = "cust-9";
        public String taxNumber = "NL123456789B01";
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomRedactorConfiguration {
        @Bean
        LogRedactor logRedactor() {
            return new LogRedactor() {
                @Override
                public String toSafeJson(Object value) {
                    return "replaced";
                }

                @Override
                public String toSafeJson(Object value, int maxLength) {
                    return "replaced";
                }

                @Override
                public String redactValue(Class<?> owner, String property, Object value) {
                    return "replaced";
                }

                @Override
                public String redactValue(String property, Object value) {
                    return "replaced";
                }

                @Override
                public String redactText(String text) {
                    return "replaced";
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomRedactionConfiguration {
        @Bean
        ValueRedaction initials() {
            return new ValueRedaction() {
                @Override
                public String name() {
                    return "initials";
                }

                @Override
                public String redact(Object value, FieldPolicy policy) {
                    return "I.";
                }
            };
        }

        @Bean
        ValueRedaction replacesMask() {
            return new ValueRedaction() {
                @Override
                public String name() {
                    return PolicyType.MASK.name();
                }

                @Override
                public String redact(Object value, FieldPolicy policy) {
                    return "[hidden]";
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomTokenizerConfiguration {
        @Bean
        Tokenizer tokenizer() {
            return value -> "tok-" + value;
        }
    }

    @Test
    void the_policy_source_can_be_explained_for_diagnostics() {
        runner.run(context -> assertThat(context.getBean(PolicyRegistry.class)
                .describe(io.xlogpolicy.core.policy.PropertyRef.of(Account.class, "iban")))
                .isEqualTo("MASK (from @LogPolicy)"));
    }
}
