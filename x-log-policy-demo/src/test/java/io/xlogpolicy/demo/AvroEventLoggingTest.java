package io.xlogpolicy.demo;

import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.demo.events.CustomerRegistered;
import io.xlogpolicy.demo.events.PostalAddress;
import org.apache.avro.specific.SpecificData;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the Avro half of the contract: the policy is declared in the {@code .avsc}, the class is generated
 * by {@code avro-maven-plugin}, and both the injected redactor and the generated {@code toString()} obey it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = "x-log-policy.hmac.secret=demo-secret")
class AvroEventLoggingTest {

    @Autowired
    LogRedactor redactor;

    @Test
    void the_redactor_applies_the_policies_from_the_avro_schema() {
        String json = redactor.toSafeJson(event());

        assertThat(json)
                .contains("\"customerId\":\"c-42\"")
                .containsPattern("\"email\":\"hmac:[0-9a-f]{8}\"")
                .contains("\"ssn\":\"***\"")
                .contains("\"cardNumber\":\"************1234\"")
                .containsPattern("\"phoneNumbers\":\\[\"sha256:[0-9a-f]{8}\"]")
                .contains("\"address\":{\"street\":\"***\",\"postalCode\":\"****AB\",\"city\":\"Amsterdam\",\"country\":\"NL\"}")
                .doesNotContain("internalNote", "ada@example.com", "123-45-6789", "4111111111111234",
                        "+31612345678", "Hollandstraat");
    }

    @Test
    void the_generated_toString_is_redacted_too() {
        CustomerRegistered event = event();

        assertThat(event.toString()).isEqualTo(redactor.toSafeJson(event));
        assertThat(String.valueOf(event)).doesNotContain("123-45-6789");
    }

    @Test
    void the_unredacted_form_stays_reachable_on_purpose() {
        assertThat(SpecificData.get().toString(event())).contains("123-45-6789");
    }

    private static CustomerRegistered event() {
        return CustomerRegistered.newBuilder()
                .setCustomerId("c-42")
                .setEmail("ada@example.com")
                .setSsn("123-45-6789")
                .setCardNumber("4111111111111234")
                .setPhoneNumbers(List.of("+31612345678"))
                .setInternalNote("chargeback dispute")
                .setRegisteredAt(Instant.parse("2026-10-11T09:00:00Z"))
                .setAddress(PostalAddress.newBuilder()
                        .setStreet("Hollandstraat 1").setPostalCode("1012AB")
                        .setCity("Amsterdam").setCountry("NL").build())
                .build();
    }
}
