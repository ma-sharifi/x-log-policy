package io.xlogpolicy.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.xlogpolicy.core.fixtures.Address;
import io.xlogpolicy.core.fixtures.Customer;
import io.xlogpolicy.core.fixtures.Redactors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LogRedactorTest {

    private final LogRedactor redactor = Redactors.standard();

    @Nested
    @DisplayName("each policy")
    class Policies {

        private final String json = redactor.toSafeJson(Customer.sample());

        @Test
        void safe_values_are_logged_verbatim() {
            assertThat(json).contains("\"id\":\"c-17\"").contains("\"age\":36");
        }

        @Test
        void mask_replaces_the_whole_value() {
            assertThat(json).contains("\"ssn\":\"***\"").doesNotContain("123-45-6789");
        }

        @Test
        void mask_applies_to_non_string_values_too() {
            assertThat(json).contains("\"creditScore\":\"***\"").doesNotContain("720");
        }

        @Test
        void partial_keeps_only_the_trailing_characters() {
            assertThat(json).contains("\"cardNumber\":\"************1234\"")
                    .doesNotContain("4111111111111234");
        }

        @Test
        void hmac_is_keyed_and_deterministic() {
            String again = redactor.toSafeJson(Customer.sample());
            assertThat(json).contains("\"email\":\"hmac:").doesNotContain("ada@example.com");
            assertThat(field(json, "email")).isEqualTo(field(again, "email"));
        }

        @Test
        void hash_is_unkeyed_sha256() {
            assertThat(json).contains("\"phone\":\"sha256:").doesNotContain("1234 5678");
        }

        @Test
        void drop_removes_the_property() {
            assertThat(json).doesNotContain("internalNote").doesNotContain("chargeback");
        }

        @Test
        void custom_dispatches_by_name() {
            assertThat(json).contains("\"fullName\":\"A.L.\"").doesNotContain("Ada Lovelace");
        }
    }

    @Nested
    @DisplayName("fail-closed defaulting")
    class FailClosed {

        @Test
        void a_value_with_no_policy_is_masked() {
            assertThat(redactor.toSafeJson(Customer.sample()))
                    .contains("\"nickname\":\"***\"")
                    .doesNotContain("\"Ada\"");
        }

        @Test
        void a_nested_object_with_no_policy_is_descended_into() {
            String json = redactor.toSafeJson(Customer.sample());
            assertThat(json).contains("\"city\":\"Amsterdam\"")   // safe inside the nested bean
                    .contains("\"street\":\"***\"")                // masked inside the nested bean
                    .contains("\"postalCode\":\"***\"")            // defaulted inside the nested bean
                    .doesNotContain("Hollandstraat 1")
                    .doesNotContain("1012 AB");
        }

        @Test
        void the_default_policy_is_configurable_for_fail_open_deployments() {
            String json = Redactors.withDefaultPolicy(PolicyType.SAFE).toSafeJson(Customer.sample());
            assertThat(json).contains("\"nickname\":\"Ada\"")
                    .contains("\"ssn\":\"***\"");   // explicit policies still win
        }
    }

    @Nested
    @DisplayName("containers")
    class Containers {

        private final String json = redactor.toSafeJson(Customer.sample());

        @Test
        void a_safe_collection_is_logged_verbatim() {
            assertThat(json).contains("\"tags\":[\"premium\",\"eu\"]");
        }

        @Test
        void a_collection_of_values_with_no_policy_has_every_element_masked() {
            assertThat(json).contains("\"priorAddresses\":[\"***\",\"***\"]")
                    .doesNotContain("Kerkstraat 9");
        }

        @Test
        void a_policied_collection_has_every_element_redacted() {
            assertThat(json).contains("\"accountNumbers\":[\"***\",\"***\"]")
                    .doesNotContain("NL91ABNA0417164300");
        }

        @Test
        void a_collection_of_beans_is_descended_into() {
            assertThat(json).contains("\"previousAddresses\":[{").contains("\"country\":\"NL\"");
        }

        @Test
        void free_form_map_keys_are_resolved_by_name() {
            // No annotation can describe a map key, so with an annotations-only registry every entry
            // falls back to the default. PolicyPrecedenceTest covers keys the OpenAPI registry knows.
            assertThat(json).contains("\"ssn\":\"***\"").doesNotContain("987-65-4321");
            assertThat(field(json, "segment")).isEqualTo("***");
        }

        @Test
        void an_arrays_element_count_is_capped() {
            List<String> many = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                many.add("secret-" + i);
            }
            Customer customer = Customer.sample();
            customer.accountNumbers = many;
            RedactionSettings settings = RedactionSettings.builder()
                    .hmacSecret("test-key").maxCollectionSize(3).build();
            assertThat(Redactors.withSettings(settings).toSafeJson(customer))
                    .contains("\"accountNumbers\":[\"***\",\"***\",\"***\",\"…(17 more elements)\"]");
        }
    }

    @Nested
    @DisplayName("robustness: logging must never break the caller")
    class Robustness {

        @Test
        void a_throwing_getter_yields_a_placeholder_instead_of_an_exception() {
            String json = redactor.toSafeJson(new Exploding());
            assertThat(json).startsWith("{\"_redactionError\":")
                    .contains(Exploding.class.getName());
        }

        @Test
        void a_cycle_is_bounded_rather_than_overflowing_the_stack() {
            Node first = new Node("first");
            Node second = new Node("second");
            first.next = second;
            second.next = first;
            assertThat(redactor.toSafeJson(first)).startsWith("{\"_redactionError\":");
        }

        @Test
        void null_is_rendered_as_null() {
            assertThat(redactor.toSafeJson(null)).isEqualTo("null");
            Customer customer = Customer.sample();
            customer.ssn = null;
            assertThat(redactor.toSafeJson(customer)).contains("\"ssn\":null");
        }

        @Test
        void output_is_clipped_to_the_configured_length() {
            String full = redactor.toSafeJson(Customer.sample());
            assertThat(redactor.toSafeJson(Customer.sample(), 20))
                    .startsWith(full.substring(0, 20))
                    .endsWith("…(truncated, " + full.length() + " chars)");
        }

        @Test
        void a_long_safe_string_is_truncated() {
            Address address = Address.sample();
            address.city = "x".repeat(50);
            RedactionSettings settings = RedactionSettings.builder()
                    .hmacSecret("test-key").maxStringLength(10).build();
            assertThat(Redactors.withSettings(settings).toSafeJson(address))
                    .contains("\"city\":\"xxxxxxxxxx…(40 more chars)\"");
        }
    }

    @Nested
    @DisplayName("shapes other than plain beans")
    class Shapes {

        @Test
        void records_are_supported() {
            String json = redactor.toSafeJson(new Payment("p-1", "4111111111111234"));
            assertThat(json).contains("\"reference\":\"p-1\"")
                    .contains("\"pan\":\"***\"")
                    .doesNotContain("4111111111111234");
        }

        @Test
        void a_renamed_property_keeps_its_policy() {
            String json = redactor.toSafeJson(new Renamed("123-45-6789"));
            assertThat(json).contains("\"social_security_number\":\"***\"").doesNotContain("123-45");
        }

        @Test
        void private_fields_without_getters_are_still_covered() {
            assertThat(redactor.toSafeJson(new NoGetters())).contains("\"token\":\"***\"")
                    .doesNotContain("super-secret");
        }

        @Test
        void a_type_level_policy_applies_to_every_property() {
            assertThat(redactor.toSafeJson(new AllSafe())).contains("\"note\":\"nothing sensitive\"");
        }

        @Test
        void a_bare_map_is_resolved_by_key_name() {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("ssn", "123-45-6789");
            payload.put("nested", Map.of("cardNumber", "4111111111111234"));
            // A top level map has no declaring type, so the by-name index and the default apply.
            assertThat(redactor.toSafeJson(payload))
                    .doesNotContain("123-45-6789")
                    .doesNotContain("4111111111111234");
        }
    }

    @Nested
    @DisplayName("single values and free-form text")
    class SingleValues {

        @Test
        void a_value_is_redacted_by_its_declaring_type_and_property() {
            assertThat(redactor.redactValue(Customer.class, "ssn", "123-45-6789")).isEqualTo("***");
            assertThat(redactor.redactValue(Customer.class, "id", "c-17")).isEqualTo("c-17");
        }

        @Test
        void text_redaction_only_applies_explicit_policies() {
            // "ssn" is explicitly policied on Customer, so it is masked even in free-form text;
            // an unrelated field is left alone rather than being masked by the default.
            String message = "{\"ssn\":\"123-45-6789\",\"comment\":\"all fine\"}";
            assertThat(redactor.redactText(message)).isEqualTo(message);
        }
    }

    private static String field(String json, String name) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("\"" + name + "\":\"([^\"]*)\"").matcher(json);
        return matcher.find() ? matcher.group(1) : null;
    }

    static class Exploding {
        public String getBoom() {
            throw new IllegalStateException("card 4111111111111234 must not reach the log");
        }
    }

    static class Node {
        @LogPolicy(PolicyType.SAFE)
        public String name;
        public Node next;

        Node(String name) {
            this.name = name;
        }
    }

    record Payment(@LogPolicy(PolicyType.SAFE) String reference, @LogPolicy(PolicyType.MASK) String pan) {
    }

    static class Renamed {
        @JsonProperty("social_security_number")
        @LogPolicy(PolicyType.MASK)
        public String socialSecurityNumber;

        Renamed(String value) {
            this.socialSecurityNumber = value;
        }
    }

    static class NoGetters {
        private final String token = "super-secret";
    }

    @LogPolicy(PolicyType.SAFE)
    static class AllSafe {
        public String note = "nothing sensitive";
    }
}
