package io.xlogpolicy.spring;

import io.xlogpolicy.avro.AvroLogRedactor;
import io.xlogpolicy.core.LogRedactor;
import org.apache.avro.Schema;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.generic.GenericRecordBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class XLogPolicyAvroAutoConfigurationTest {

    private static final Schema PAYMENT = new Schema.Parser().parse("""
            {"type": "record", "name": "PaymentMade", "fields": [
              {"name": "id",   "type": "string", "x-log-policy": "SAFE"},
              {"name": "iban", "type": "string", "x-log-policy": "MASK"}
            ]}""");

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    XLogPolicyAutoConfiguration.class, XLogPolicyAvroAutoConfiguration.class));

    @AfterEach
    void clearStaticHolders() {
        LogPolicyStaticHolder.reset();
        AvroLogRedactor.install(null);
    }

    @Test
    void the_redactor_reads_policies_from_the_avro_schema() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(LogRedactor.class);
            assertThat(context.getBean(LogRedactor.class).toSafeJson(payment()))
                    .isEqualTo("{\"id\":\"p-1\",\"iban\":\"***\"}");
        });
    }

    @Test
    void the_same_redactor_still_handles_everything_else() {
        runner.run(context -> assertThat(context.getBean(LogRedactor.class).toSafeJson(Map.of("k", "v")))
                .isEqualTo("{\"k\":\"***\"}"));
    }

    @Test
    void configuration_overrides_apply_to_avro_records() {
        runner.withPropertyValues("x-log-policy.overrides.[PaymentMade.id]=DROP").run(context ->
                assertThat(context.getBean(LogRedactor.class).toSafeJson(payment()))
                        .isEqualTo("{\"iban\":\"***\"}"));
    }

    @Test
    void generated_toString_uses_the_configured_redactor() {
        runner.run(context -> assertThat(AvroLogRedactor.shared()).isSameAs(context.getBean(LogRedactor.class)));
    }

    private static GenericRecord payment() {
        return new GenericRecordBuilder(PAYMENT).set("id", "p-1").set("iban", "NL91ABNA0417164300").build();
    }
}
