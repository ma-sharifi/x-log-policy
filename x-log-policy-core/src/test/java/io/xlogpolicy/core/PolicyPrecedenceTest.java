package io.xlogpolicy.core;

import io.xlogpolicy.core.fixtures.Customer;
import io.xlogpolicy.core.fixtures.Redactors;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.policy.PropertyRef;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The order is: configuration override, then {@code @LogPolicy}, then the OpenAPI registry for the
 * matching schema, then the registry by property name, then the default.
 */
class PolicyPrecedenceTest {

    private static final LogPolicyMetadata METADATA = LogPolicyMetadata.builder()
            .add("Customer", "nickname", FieldPolicy.of(PolicyType.SAFE))
            .add("Customer", "ssn", FieldPolicy.of(PolicyType.HASH))
            .add("Ticket", "segment", FieldPolicy.partial(2))
            .build();

    @Test
    void an_override_beats_an_annotation() {
        Map<String, String> overrides = Map.of("Customer.ssn", "PARTIAL:2");
        String json = Redactors.withChain(overrides, METADATA).toSafeJson(Customer.sample());
        assertThat(json).contains("\"ssn\":\"*********89\"");
    }

    @Test
    void an_annotation_beats_the_openapi_registry() {
        // The registry says HASH for Customer.ssn, the annotation says MASK. The free-form map is
        // cleared here because a map key has no annotation to beat: it resolves through the registry,
        // which is exactly what the next test covers.
        Customer customer = Customer.sample();
        customer.attributes = null;
        assertThat(Redactors.withChain(Map.of(), METADATA).toSafeJson(customer))
                .contains("\"ssn\":\"***\"")
                .doesNotContain("sha256:ecdbc061");
    }

    @Test
    void the_openapi_registry_beats_the_default() {
        assertThat(Redactors.withChain(Map.of(), METADATA).toSafeJson(Customer.sample()))
                .contains("\"nickname\":\"Ada\"");
    }

    @Test
    void a_map_key_is_resolved_through_the_by_field_name_index() {
        // "segment" is declared on Ticket, not Customer, so only the by-name index can supply it;
        // "ssn" in the same map resolves to the registry policy, since no annotation describes a key.
        Customer customer = Customer.sample();
        customer.attributes = new LinkedHashMap<>();
        customer.attributes.put("segment", "gold");
        customer.attributes.put("ssn", "987-65-4321");
        assertThat(Redactors.withChain(Map.of(), METADATA).toSafeJson(customer))
                .contains("\"segment\":\"**ld\"")
                .contains("\"ssn\":\"sha256:")
                .doesNotContain("987-65-4321");
    }

    @Test
    void a_nested_free_form_object_is_descended_into_rather_than_masked_whole() {
        // "shipping" holds an object and declares nothing, so its keys are resolved individually:
        // masking the container would hide the parts the contract says are safe.
        Customer customer = Customer.sample();
        customer.attributes = new LinkedHashMap<>();
        customer.attributes.put("shipping", new LinkedHashMap<>(Map.of("nickname", "Ada", "ssn", "1")));
        customer.attributes.put("history", java.util.List.of(new LinkedHashMap<>(Map.of("nickname", "Grace"))));

        String json = Redactors.withChain(Map.of(), METADATA).toSafeJson(customer);

        assertThat(json).contains("\"nickname\":\"Ada\"")      // SAFE per the registry
                .contains("\"nickname\":\"Grace\"")            // also inside a list of objects
                .contains("\"ssn\":\"sha256:");                 // still redacted per the registry
    }

    @Test
    void a_wildcard_override_applies_to_every_type() {
        assertThat(Redactors.withChain(Map.of("*.nickname", "DROP"), METADATA).toSafeJson(Customer.sample()))
                .doesNotContain("nickname");
    }

    @Test
    void an_override_key_is_matched_case_insensitively_and_by_fully_qualified_name() {
        assertThat(Redactors.withChain(Map.of("customer.NICKNAME", "SAFE"), LogPolicyMetadata.empty())
                .toSafeJson(Customer.sample())).contains("\"nickname\":\"Ada\"");
        assertThat(Redactors.withChain(Map.of(Customer.class.getName() + ".nickname", "SAFE"),
                LogPolicyMetadata.empty()).toSafeJson(Customer.sample())).contains("\"nickname\":\"Ada\"");
    }

    @Test
    void the_source_of_a_policy_can_be_explained() {
        PolicyRegistry registry = PolicyRegistry.standard(
                Map.of("Customer.cardNumber", "DROP"), METADATA, FieldPolicy.of(PolicyType.MASK));
        assertThat(registry.describe(PropertyRef.of(Customer.class, "cardNumber")))
                .isEqualTo("DROP (from configuration-override)");
        assertThat(registry.describe(PropertyRef.of(Customer.class, "ssn")))
                .isEqualTo("MASK (from @LogPolicy)");
        assertThat(registry.describe(PropertyRef.of(Customer.class, "nickname")))
                .isEqualTo("SAFE (from openapi-metadata)");
        assertThat(registry.describe(PropertyRef.of(Customer.class, "unknownField")))
                .isEqualTo("MASK (default)");
    }

    @Test
    void a_schema_is_matched_after_stripping_a_generator_suffix() {
        LogPolicyMetadata metadata = LogPolicyMetadata.builder()
                .add("Customer", "nickname", FieldPolicy.of(PolicyType.SAFE))
                .build();
        PolicyRegistry registry = PolicyRegistry.standard(Map.of(), metadata, FieldPolicy.of(PolicyType.MASK));
        assertThat(registry.resolve(PropertyRef.of(CustomerDto.class, "nickname")).type())
                .isEqualTo(PolicyType.SAFE);
    }

    static class CustomerDto {
        public String nickname;
    }
}
