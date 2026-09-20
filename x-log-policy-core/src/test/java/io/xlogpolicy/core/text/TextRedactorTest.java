package io.xlogpolicy.core.text;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.fixtures.Redactors;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.policy.PolicyRegistry;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TextRedactorTest {

    private static final LogPolicyMetadata METADATA = LogPolicyMetadata.builder()
            .add("Customer", "ssn", FieldPolicy.of(PolicyType.MASK))
            .add("Customer", "cardNumber", FieldPolicy.partial(4))
            .add("Customer", "creditScore", FieldPolicy.of(PolicyType.MASK))
            .add("Customer", "internalNote", FieldPolicy.of(PolicyType.DROP))
            .add("Customer", "city", FieldPolicy.of(PolicyType.SAFE))
            .build();

    private final TextRedactor redactor = new TextRedactor(
            PolicyRegistry.standard(Map.of(), METADATA, FieldPolicy.of(PolicyType.MASK)), Redactors.engine());

    @Test
    void a_policied_string_value_is_replaced() {
        assertThat(redactor.redact("{\"ssn\":\"123-45-6789\",\"city\":\"Amsterdam\"}"))
                .isEqualTo("{\"ssn\":\"***\",\"city\":\"Amsterdam\"}");
    }

    @Test
    void a_policied_number_is_replaced() {
        assertThat(redactor.redact("{\"creditScore\":720}")).isEqualTo("{\"creditScore\":\"***\"}");
    }

    @Test
    void parameters_such_as_partial_length_are_honoured() {
        assertThat(redactor.redact("{ \"cardNumber\" : \"4111111111111234\" }"))
                .isEqualTo("{ \"cardNumber\" : \"************1234\" }");
    }

    @Test
    void drop_becomes_a_mask_because_text_cannot_be_rewritten_safely() {
        assertThat(redactor.redact("{\"internalNote\":\"chargeback\"}"))
                .isEqualTo("{\"internalNote\":\"***\"}");
    }

    @Test
    void the_default_policy_is_not_applied_to_free_form_text() {
        // Masking every unknown key would destroy unrelated log messages; only declared fields are hit.
        String message = "{\"orderId\":\"o-9\",\"total\":42}";
        assertThat(redactor.redact(message)).isEqualTo(message);
    }

    @Test
    void text_that_is_not_json_is_left_alone() {
        assertThat(redactor.redact("started in 412ms")).isEqualTo("started in 412ms");
        assertThat(redactor.redact(null)).isNull();
    }

    @Test
    void embedded_json_inside_a_log_line_is_still_covered() {
        assertThat(redactor.redact("rejected payload {\"ssn\":\"123-45-6789\"} from 10.0.0.1"))
                .isEqualTo("rejected payload {\"ssn\":\"***\"} from 10.0.0.1");
    }

    @Test
    void escaped_characters_do_not_break_the_scan() {
        assertThat(redactor.redact("{\"ssn\":\"12\\\"34\",\"city\":\"Ams\\\\terdam\"}"))
                .isEqualTo("{\"ssn\":\"***\",\"city\":\"Ams\\\\terdam\"}");
    }

    @Test
    void a_value_that_was_already_redacted_is_not_redacted_again() {
        // Log messages routinely contain output that went through the redactor. PARTIAL, HASH and HMAC
        // are not idempotent, so re-applying them would corrupt what is already safe.
        String alreadySafe = "{\"ssn\":\"***\",\"cardNumber\":\"************1234\"}";
        assertThat(redactor.redact(alreadySafe)).isEqualTo(alreadySafe);

        String digests = "{\"ssn\":\"sha256:9f86d081\",\"cardNumber\":\"hmac:7d3a9c12\"}";
        assertThat(redactor.redact(digests)).isEqualTo(digests);
    }

    @Test
    void redacting_twice_gives_the_same_result_as_redacting_once() {
        String once = redactor.redact("{\"cardNumber\":\"4111111111111234\"}");
        assertThat(redactor.redact(once)).isEqualTo(once);
    }

    @Test
    void a_null_value_stays_null() {
        assertThat(redactor.redact("{\"ssn\":null}")).isEqualTo("{\"ssn\":null}");
    }
}
