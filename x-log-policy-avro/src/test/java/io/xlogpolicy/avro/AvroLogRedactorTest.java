package io.xlogpolicy.avro;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.JacksonLogRedactor;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import io.xlogpolicy.core.policy.OverridePolicyResolver;
import io.xlogpolicy.core.redaction.RedactionEngine;
import org.apache.avro.Schema;
import org.apache.avro.SchemaBuilder;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericRecord;
import org.apache.avro.generic.GenericRecordBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AvroLogRedactorTest {

    private static final Schema CUSTOMER = load("/avro/customer-event.avsc");
    private static final Schema ADDRESS = CUSTOMER.getField("priorAddresses").schema().getElementType();

    private final AvroLogRedactor redactor = AvroLogRedactor.withDefaults();

    @Test
    void every_field_is_rendered_through_the_policy_its_schema_declares() {
        String json = redactor.toSafeJson(customer());

        assertThat(json)
                .contains("\"id\":\"c-42\"")
                .containsPattern("\"email\":\"hmac:[0-9a-f]{8}\"")
                .contains("\"ssn\":\"***\"")
                .contains("\"cardNumber\":\"************1234\"")
                .containsPattern("\"phoneNumbers\":\\[\"sha256:[0-9a-f]{8}\",\"sha256:[0-9a-f]{8}\"]")
                .contains("\"nickname\":\"****lace\"")
                .contains("\"loyaltyPoints\":340")
                .contains("\"status\":\"ACTIVE\"")
                .contains("\"attributes\":{\"segment\":\"***\"}");
        assertThat(json).doesNotContain("123-45-6789", "ada@example.com", "4111111111111234", "+31612345678");
    }

    @Test
    void drop_removes_the_field_entirely() {
        assertThat(redactor.toSafeJson(customer())).doesNotContain("internalNote", "chargeback");
    }

    @Test
    void an_undeclared_field_is_masked() {
        assertThat(redactor.toSafeJson(customer())).contains("\"undeclared\":\"***\"");
    }

    @Test
    void a_nested_record_is_descended_into_and_applies_its_own_policies() {
        String json = redactor.toSafeJson(customer());

        assertThat(json).contains("\"address\":{\"street\":\"***\",\"postalCode\":\"****AB\",\"city\":\"Amsterdam\"}");
        assertThat(json).contains("\"priorAddresses\":[{\"street\":\"***\",\"postalCode\":\"****CD\",\"city\":\"Utrecht\"}]");
        assertThat(json).doesNotContain("Hollandstraat", "Oudegracht");
    }

    @Test
    void a_record_level_policy_is_the_default_for_its_fields() {
        Schema schema = new Schema.Parser().parse("""
                {"type": "record", "name": "Audit", "x-log-policy": "HASH", "fields": [
                  {"name": "actor",  "type": "string"},
                  {"name": "action", "type": "string", "x-log-policy": "SAFE"}
                ]}""");
        GenericRecord audit = new GenericRecordBuilder(schema).set("actor", "ada").set("action", "login").build();

        assertThat(redactor.toSafeJson(audit)).matches("\\{\"actor\":\"sha256:[0-9a-f]{8}\",\"action\":\"login\"}");
    }

    @Test
    void a_configuration_override_beats_the_schema() {
        AvroLogRedactor overridden = new AvroLogRedactor(JacksonLogRedactor.withDefaults(),
                RedactionEngine.withDefaults(),
                new OverridePolicyResolver(Map.of("CustomerEvent.id", "MASK", "*.city", "DROP")),
                FieldPolicy.of(PolicyType.MASK));

        String json = overridden.toSafeJson(customer());

        assertThat(json).contains("\"id\":\"***\"").doesNotContain("city", "Amsterdam");
    }

    @Test
    void a_malformed_declaration_fails_closed() {
        Schema schema = new Schema.Parser().parse("""
                {"type": "record", "name": "Broken", "fields": [
                  {"name": "secret", "type": "string", "x-log-policy": "SHOUT"}
                ]}""");
        GenericRecord broken = new GenericRecordBuilder(schema).set("secret", "hunter2").build();

        assertThat(redactor.toSafeJson(broken)).isEqualTo("{\"secret\":\"***\"}");
    }

    @Test
    void non_avro_values_go_to_the_delegate() {
        assertThat(redactor.toSafeJson(Map.of("k", "v"))).isEqualTo(JacksonLogRedactor.withDefaults()
                .toSafeJson(Map.of("k", "v")));
        assertThat(redactor.toSafeJson(null)).isEqualTo("null");
    }

    @Test
    void collections_and_depth_are_bounded() {
        RedactionEngine engine = new RedactionEngine(
                RedactionSettings.builder().maxCollectionSize(1).maxDepth(2).build(), null, List.of());
        AvroLogRedactor bounded = new AvroLogRedactor(JacksonLogRedactor.withDefaults(), engine,
                OverridePolicyResolver.none(), FieldPolicy.of(PolicyType.MASK));

        String json = bounded.toSafeJson(customer());

        assertThat(json).containsPattern("\"phoneNumbers\":\\[\"sha256:[0-9a-f]{8}\",\"…\\(1 more elements\\)\"]");
        assertThat(json).contains("\"priorAddresses\":[\"…(max depth 2)\"]");
    }

    @Test
    void the_rendered_json_is_truncated_past_the_limit() {
        assertThat(redactor.toSafeJson(customer(), 20)).startsWith("{\"id\":\"c-42\"").contains("…(truncated, ");
    }

    @Test
    void a_failure_to_render_is_reported_not_thrown() {
        GenericRecord record = new GenericData.Record(SchemaBuilder.record("Odd").fields()
                .name("payload").prop("x-log-policy", "SAFE").type().stringType().noDefault().endRecord()) {
            @Override
            public Object get(int i) {
                throw new IllegalStateException("ada@example.com");
            }
        };

        assertThat(redactor.toSafeJson(record))
                .isEqualTo("{\"_redactionError\":\"IllegalStateException\",\"_type\":\"Odd\"}");
    }

    private static GenericRecord customer() {
        GenericRecord address = new GenericRecordBuilder(ADDRESS)
                .set("street", "Hollandstraat 1").set("postalCode", "1012AB").set("city", "Amsterdam").build();
        GenericRecord prior = new GenericRecordBuilder(ADDRESS)
                .set("street", "Oudegracht 9").set("postalCode", "3511CD").set("city", "Utrecht").build();
        return new GenericRecordBuilder(CUSTOMER)
                .set("id", "c-42")
                .set("email", "ada@example.com")
                .set("ssn", "123-45-6789")
                .set("cardNumber", "4111111111111234")
                .set("phoneNumbers", List.of("+31612345678", "+31687654321"))
                .set("nickname", "Lovelace")
                .set("internalNote", "chargeback dispute")
                .set("loyaltyPoints", 340)
                .set("undeclared", "who knows")
                .set("status", new GenericData.EnumSymbol(CUSTOMER.getField("status").schema(), "ACTIVE"))
                .set("address", address)
                .set("priorAddresses", List.of(prior))
                .set("attributes", Map.of("segment", "premium"))
                .build();
    }

    private static Schema load(String resource) {
        try (InputStream in = AvroLogRedactorTest.class.getResourceAsStream(resource)) {
            return new Schema.Parser().parse(in);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
