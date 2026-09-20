package io.xlogpolicy.demo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The claim this project makes, tested end to end: the API keeps returning real data while nothing
 * sensitive reaches the log — through the service's own {@code LogRedactor} call and through the HTTP
 * filter, with policies coming from the OpenAPI document alone.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class CustomerApiIntegrationTest {

    private static final String PAYLOAD = """
            {
              "id": "c-17",
              "email": "ada@example.com",
              "ssn": "123-45-6789",
              "cardNumber": "4111111111111234",
              "fullName": "Ada Lovelace",
              "internalNote": "called twice about the chargeback",
              "phoneNumbers": ["+31612345678", "+31687654321"],
              "tags": ["premium", "eu"],
              "loyaltyPoints": 340,
              "attributes": {"segment": "gold"},
              "address": {
                "street": "Hollandstraat",
                "houseNumber": "1",
                "postalCode": "1012AB",
                "city": "Amsterdam",
                "country": "NL"
              }
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void the_api_returns_real_data_while_the_log_shows_only_what_the_spec_allows(CapturedOutput output)
            throws Exception {
        String response = mockMvc.perform(post("/customers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Caller-Email", "operator@example.com")
                        .content(PAYLOAD))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        // The caller's contract is untouched.
        assertThat(response).contains("123-45-6789").contains("4111111111111234").contains("Ada Lovelace");

        String logs = output.getOut();
        // SAFE fields are readable.
        assertThat(logs).contains("\"id\":\"c-17\"")
                .contains("\"city\":\"Amsterdam\"")
                .contains("\"loyaltyPoints\":340")
                .contains("\"tags\":[\"premium\",\"eu\"]");
        // Each policy did its job.
        assertThat(logs).contains("\"ssn\":\"***\"")
                .contains("\"cardNumber\":\"************1234\"")
                .contains("\"email\":\"hmac:")
                .contains("\"fullName\":\"A.L.\"")
                .contains("\"postalCode\":\"****AB\"")
                .contains("\"phoneNumbers\":[\"sha256:");
        // DROP means the property is not in the output at all.
        assertThat(logs).doesNotContain("internalNote");
        // And no raw personal data anywhere, in any log line.
        assertThat(logs)
                .doesNotContain("123-45-6789")
                .doesNotContain("4111111111111234")
                .doesNotContain("ada@example.com")
                .doesNotContain("operator@example.com")
                .doesNotContain("Ada Lovelace")
                .doesNotContain("Hollandstraat")
                .doesNotContain("+31612345678")
                .doesNotContain("chargeback")
                .doesNotContain("1012AB");
    }

    @Test
    void a_lookup_logs_its_identifier_because_the_spec_says_it_is_safe(CapturedOutput output) throws Exception {
        mockMvc.perform(post("/customers").contentType(MediaType.APPLICATION_JSON).content(PAYLOAD))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/customers/c-17")).andExpect(status().isOk());

        assertThat(output.getOut()).contains("lookup of customer c-17 hit");
    }

    @Test
    void a_field_the_spec_never_mentioned_is_masked_in_the_request_log(CapturedOutput output) throws Exception {
        mockMvc.perform(post("/customers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"id\":\"c-18\",\"email\":\"grace@example.com\","
                                + "\"undocumentedField\":\"added by a client last night\"}"))
                .andExpect(status().isCreated());

        // Fail-closed: the HTTP filter resolves body keys by name, so an unknown key cannot leak.
        assertThat(output.getOut())
                .doesNotContain("added by a client last night")
                .doesNotContain("grace@example.com");
    }
}
