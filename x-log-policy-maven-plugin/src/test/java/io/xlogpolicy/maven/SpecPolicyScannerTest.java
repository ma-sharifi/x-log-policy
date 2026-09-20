package io.xlogpolicy.maven;

import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class SpecPolicyScannerTest {

    private static final LogPolicyMetadata METADATA = scan("full-coverage.yaml").metadata();

    static SpecPolicyScanner.ScanResult scan(String fixture) {
        Path path = Path.of("src", "test", "resources", fixture).toAbsolutePath();
        return SpecPolicyScanner.scan(path.toString());
    }

    @Test
    void the_scalar_shorthand_is_read() {
        assertThat(METADATA.find("Customer", "ssn").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        assertThat(METADATA.find("Customer", "id").orElseThrow().type()).isEqualTo(PolicyType.SAFE);
    }

    @Test
    void policy_names_are_case_insensitive() {
        assertThat(METADATA.find("Customer", "email").orElseThrow().type()).isEqualTo(PolicyType.HMAC);
    }

    @Test
    void the_object_form_carries_parameters() {
        assertThat(METADATA.find("Customer", "cardNumber").orElseThrow().keep()).isEqualTo(4);
        assertThat(METADATA.find("Customer", "loyaltyId").orElseThrow().customName()).isEqualTo("loyalty");
    }

    @Test
    void a_referenced_schema_keeps_its_own_name() {
        assertThat(METADATA.find("Address", "street").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        assertThat(METADATA.find("Address", "city").orElseThrow().type()).isEqualTo(PolicyType.SAFE);
        // ... and is not re-indexed under a synthetic name derived from the referencing property.
        assertThat(METADATA.find("CustomerAddress", "street")).isEmpty();
    }

    @Test
    void an_inline_object_is_indexed_under_the_name_a_generator_would_give_it() {
        assertThat(METADATA.find("CustomerContact", "phone").orElseThrow().type()).isEqualTo(PolicyType.HASH);
        assertThat(METADATA.find("CustomerContact", "preferredName").orElseThrow().type())
                .isEqualTo(PolicyType.SAFE);
    }

    @Test
    void a_policy_on_array_items_covers_the_property() {
        assertThat(METADATA.find("Customer", "priorAddresses").orElseThrow().type()).isEqualTo(PolicyType.MASK);
    }

    @Test
    void a_policy_on_additional_properties_covers_the_map() {
        assertThat(METADATA.find("Customer", "attributes").orElseThrow().type()).isEqualTo(PolicyType.MASK);
    }

    @Test
    void a_schema_level_policy_is_inherited_by_its_properties() {
        assertThat(METADATA.find("Secret", "clientId").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        assertThat(METADATA.find("Secret", "clientSecret").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        // An explicit property policy still wins over the schema default.
        assertThat(METADATA.find("Secret", "label").orElseThrow().type()).isEqualTo(PolicyType.SAFE);
    }

    @Test
    void composed_schemas_contribute_their_properties() {
        assertThat(METADATA.find("Employee", "employeeNumber").orElseThrow().type()).isEqualTo(PolicyType.HMAC);
    }

    @Test
    void parameters_and_headers_are_indexed_for_the_http_layer() {
        assertThat(METADATA.find(SpecPolicyScanner.PARAMETERS_SCHEMA, "X-Caller-Email").orElseThrow().type())
                .isEqualTo(PolicyType.HMAC);
        assertThat(METADATA.find(SpecPolicyScanner.PARAMETERS_SCHEMA, "customerId").orElseThrow().type())
                .isEqualTo(PolicyType.SAFE);
        assertThat(METADATA.find(SpecPolicyScanner.PARAMETERS_SCHEMA, "X-Trace-Id")).isPresent();
    }

    @Test
    void an_inline_request_body_is_indexed_under_the_operation() {
        assertThat(METADATA.find("RecordAuditRequest", "actor").orElseThrow().type()).isEqualTo(PolicyType.HMAC);
    }

    @Test
    void the_by_field_name_index_is_populated() {
        assertThat(METADATA.findByFieldName("ssn").orElseThrow().type()).isEqualTo(PolicyType.MASK);
        assertThat(METADATA.findByFieldName("city").orElseThrow().type()).isEqualTo(PolicyType.SAFE);
    }

    @Test
    void every_property_is_reported_whether_policied_or_not() {
        SpecPolicyScanner.ScanResult result = scan("uncovered.yaml");
        assertThat(result.findings()).hasSize(3);
        assertThat(result.policiedCount()).isEqualTo(1);
        assertThat(result.findings().stream()
                .filter(finding -> !finding.hasPolicy())
                .map(SpecPolicyScanner.PropertyFinding::propertyName))
                .containsExactlyInAnyOrder("passportNumber", "countryCode");
    }

    @Test
    void an_unknown_policy_name_is_reported_as_a_problem() {
        SpecPolicyScanner.ScanResult result = scan("invalid-policy.yaml");
        assertThat(result.problems()).anySatisfy(problem ->
                assertThat(problem).contains("Customer.ssn").contains("OBFUSCATE"));
        assertThat(result.metadata().find("Customer", "ssn")).isEmpty();
    }

    @Test
    void a_property_pointing_at_another_schema_is_marked_structured() {
        // Customer.address is a $ref: the nested fields carry the policies, so the reference needs none
        // and must not be reported as uncovered.
        SpecPolicyScanner.PropertyFinding address = finding("Customer", "address");
        assertThat(address.structured()).isTrue();
        assertThat(address.needsPolicy()).isFalse();

        // An inline object is structured too.
        assertThat(finding("Customer", "contact").structured()).isTrue();

        // A leaf, and a map or array of leaves, are not.
        assertThat(finding("Customer", "ssn").structured()).isFalse();
        assertThat(finding("Customer", "priorAddresses").structured()).isFalse();
        assertThat(finding("Customer", "attributes").structured()).isFalse();
    }

    @Test
    void a_leaf_without_a_policy_is_the_only_thing_reported_as_uncovered() {
        SpecPolicyScanner.ScanResult result = scan("uncovered.yaml");
        assertThat(result.findings().stream()
                .filter(SpecPolicyScanner.PropertyFinding::needsPolicy)
                .map(SpecPolicyScanner.PropertyFinding::propertyName))
                .containsExactlyInAnyOrder("passportNumber", "countryCode");
    }

    private static SpecPolicyScanner.PropertyFinding finding(String schema, String property) {
        return scan("full-coverage.yaml").findings().stream()
                .filter(candidate -> candidate.schemaName().equals(schema)
                        && candidate.propertyName().equals(property))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no finding for " + schema + "." + property));
    }

    @Test
    void a_missing_document_is_reported_rather_than_throwing() {
        SpecPolicyScanner.ScanResult result = scan("does-not-exist.yaml");
        assertThat(result.metadata().isEmpty()).isTrue();
        assertThat(result.problems()).isNotEmpty();
    }
}
