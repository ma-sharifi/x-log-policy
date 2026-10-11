package io.xlogpolicy.maven;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AvroSchemaScannerTest {

    private final SpecPolicyScanner.ScanResult result =
            AvroSchemaScanner.scan(List.of(file("avro-address.avsc"), file("avro-customer.avsc")));

    @Test
    void policies_on_fields_and_on_their_types_reach_the_registry() {
        assertThat(result.metadata().find("CustomerCreated", "id")).contains(FieldPolicy.of(PolicyType.SAFE));
        assertThat(result.metadata().find("CustomerCreated", "email")).contains(FieldPolicy.of(PolicyType.HMAC));
        assertThat(result.metadata().find("CustomerCreated", "phones")).contains(FieldPolicy.partial(2));
        assertThat(result.metadata().find("Address", "street")).contains(FieldPolicy.of(PolicyType.MASK));
    }

    @Test
    void a_later_file_may_use_a_type_from_an_earlier_one() {
        assertThat(finding("CustomerCreated", "address")).hasValueSatisfying(finding -> {
            assertThat(finding.structured()).isTrue();
            assertThat(finding.needsPolicy()).isFalse();
        });
    }

    @Test
    void an_undeclared_leaf_is_reported_as_needing_a_policy() {
        assertThat(finding("CustomerCreated", "lastName")).hasValueSatisfying(
                finding -> assertThat(finding.needsPolicy()).isTrue());
        assertThat(finding("Address", "postalCode")).hasValueSatisfying(
                finding -> assertThat(finding.needsPolicy()).isTrue());
    }

    @Test
    void a_malformed_declaration_is_a_problem() {
        assertThat(result.problems()).singleElement().asString()
                .contains("com.example.events.CustomerCreated.bad").contains("requires a 'policy' entry");
    }

    @Test
    void an_unparseable_file_is_a_problem_not_an_exception() {
        SpecPolicyScanner.ScanResult broken = AvroSchemaScanner.scan(List.of(file("avro-customer.avsc")));

        assertThat(broken.problems()).anySatisfy(problem -> assertThat(problem).contains("could not parse"));
    }

    private Optional<SpecPolicyScanner.PropertyFinding> finding(String schema, String property) {
        return result.findings().stream()
                .filter(f -> f.schemaName().equals(schema) && f.propertyName().equals(property))
                .findFirst();
    }

    private static File file(String resource) {
        try {
            return new File(AvroSchemaScannerTest.class.getResource("/" + resource).toURI());
        } catch (URISyntaxException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
