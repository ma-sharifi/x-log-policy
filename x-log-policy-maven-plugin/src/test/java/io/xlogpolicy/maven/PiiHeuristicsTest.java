package io.xlogpolicy.maven;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PiiHeuristicsTest {

    private final PiiHeuristics defaults = new PiiHeuristics(List.of(), List.of());

    @Test
    void names_that_are_personal_data_in_any_domain_are_flagged() {
        assertThat(defaults.flag("Customer.ssn", "ssn")).isPresent();
        assertThat(defaults.flag("Customer.passportNumber", "passportNumber")).isPresent();
        assertThat(defaults.flag("Customer.email_address", "email_address")).isPresent();
        assertThat(defaults.flag("Customer.date-of-birth", "date-of-birth")).isPresent();
        assertThat(defaults.flag("Account.IBAN", "IBAN")).isPresent();
    }

    @Test
    void ordinary_names_are_not_flagged() {
        assertThat(defaults.flag("Order.orderId", "orderId")).isEmpty();
        assertThat(defaults.flag("Order.total", "total")).isEmpty();
        assertThat(defaults.flag("Customer.createdAt", "createdAt")).isEmpty();
    }

    @Test
    void an_exclusion_wins_over_a_pattern() {
        // A warehouse address is not personal data; a customer's is.
        PiiHeuristics withExclusion = new PiiHeuristics(List.of(), List.of("Warehouse\\.address"));
        assertThat(withExclusion.flag("Warehouse.address", "address")).isEmpty();
        assertThat(withExclusion.flag("Customer.address", "address")).isPresent();
    }

    @Test
    void the_pattern_list_can_be_replaced_for_a_domain() {
        PiiHeuristics custom = new PiiHeuristics(List.of("policynumber"), List.of());
        assertThat(custom.flag("Claim.policyNumber", "policyNumber")).contains("policynumber");
        assertThat(custom.flag("Customer.ssn", "ssn")).isEmpty();
    }
}
