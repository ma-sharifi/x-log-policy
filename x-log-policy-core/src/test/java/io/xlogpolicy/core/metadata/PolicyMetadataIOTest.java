package io.xlogpolicy.core.metadata;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyMetadataIOTest {

    @Test
    void a_registry_survives_a_round_trip() {
        LogPolicyMetadata original = LogPolicyMetadata.builder()
                .add("Customer", "ssn", FieldPolicy.of(PolicyType.MASK))
                .add("Customer", "cardNumber", FieldPolicy.partial(4))
                .add("Customer", "loyaltyId", FieldPolicy.custom("loyalty"))
                .add("Address", "street", new FieldPolicy(PolicyType.HMAC, -1, "", Map.of("note", "keyed")))
                .build();

        LogPolicyMetadata reloaded = PolicyMetadataIO.readFromString(PolicyMetadataIO.writeToString(original));

        assertThat(reloaded.find("Customer", "ssn")).contains(FieldPolicy.of(PolicyType.MASK));
        assertThat(reloaded.find("Customer", "cardNumber")).contains(FieldPolicy.partial(4));
        assertThat(reloaded.find("Customer", "loyaltyId")).contains(FieldPolicy.custom("loyalty"));
        assertThat(reloaded.find("Address", "street").orElseThrow().params()).containsEntry("note", "keyed");
        assertThat(reloaded.find("Customer", "absent")).isEmpty();
    }

    @Test
    void the_strictest_policy_wins_the_by_field_name_index() {
        LogPolicyMetadata metadata = LogPolicyMetadata.builder()
                .add("Customer", "email", FieldPolicy.of(PolicyType.HMAC))
                .add("Contact", "email", FieldPolicy.of(PolicyType.SAFE))
                .add("Lead", "email", FieldPolicy.of(PolicyType.MASK))
                .build();

        assertThat(metadata.findByFieldName("email").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        // Per-schema lookups keep their own answer.
        assertThat(metadata.find("Contact", "email").orElseThrow().type()).isEqualTo(PolicyType.SAFE);
    }

    @Test
    void the_written_form_is_stable_and_readable() {
        String json = PolicyMetadataIO.writeToString(LogPolicyMetadata.builder()
                .add("Customer", "ssn", FieldPolicy.of(PolicyType.MASK))
                .build());

        assertThat(json).contains("\"version\" : 1")
                .contains("\"Customer\"")
                .contains("\"policy\" : \"MASK\"")
                .contains("\"byFieldName\"");
    }

    @Test
    void registries_from_several_jars_are_merged() {
        LogPolicyMetadata first = LogPolicyMetadata.builder()
                .add("Customer", "ssn", FieldPolicy.of(PolicyType.MASK)).build();
        LogPolicyMetadata second = LogPolicyMetadata.builder()
                .add("Invoice", "iban", FieldPolicy.of(PolicyType.HMAC)).build();

        LogPolicyMetadata merged = first.merge(second);

        assertThat(merged.find("Customer", "ssn")).isPresent();
        assertThat(merged.find("Invoice", "iban")).isPresent();
    }

    @Test
    void a_shorthand_policy_string_is_accepted() {
        LogPolicyMetadata metadata = PolicyMetadataIO.readFromString("""
                {"version":1,"schemas":{"Customer":{"ssn":"mask","email":{"policy":"partial","keep":3}}}}
                """);

        assertThat(metadata.find("Customer", "ssn").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        assertThat(metadata.find("Customer", "email").orElseThrow().keep()).isEqualTo(3);
    }

    @Test
    void a_future_format_version_is_rejected_rather_than_half_understood() {
        assertThatThrownBy(() -> PolicyMetadataIO.readFromString("{\"version\":99,\"schemas\":{}}"))
                .hasRootCauseMessage("x-log-policy metadata version 99 is newer than supported version 1;"
                        + " upgrade x-log-policy-core");
    }
}
