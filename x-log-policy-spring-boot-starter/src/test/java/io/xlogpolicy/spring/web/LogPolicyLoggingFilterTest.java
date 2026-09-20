package io.xlogpolicy.spring.web;

import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.PolicyType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The end-to-end guarantee: a request carrying personal data is answered normally, and nothing sensitive
 * reaches the log — not the declared fields, and not the undeclared ones either.
 */
@SpringBootTest(properties = {
        "x-log-policy.http.enabled=true",
        "x-log-policy.http.include-response-body=true",
        "x-log-policy.http.include-headers=X-Caller-Email,Authorization,User-Agent",
        "x-log-policy.hmac.secret=test-secret",
        "logging.level.io.xlogpolicy.http=INFO"
})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class LogPolicyLoggingFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void a_request_body_is_logged_with_every_field_redacted(CapturedOutput output) throws Exception {
        mockMvc.perform(post("/customers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Caller-Email", "ada@example.com")
                        .header("Authorization", "Bearer super-secret-token")
                        .content("""
                                {"id":"c-17","ssn":"123-45-6789","cardNumber":"4111111111111234",
                                 "undocumented":"leaks without a default policy"}
                                """))
                .andExpect(status().isOk());

        assertThat(output.getOut())
                .contains("POST /customers -> 200")
                // declared policies applied to the body
                .contains("\"ssn\":\"***\"")
                .contains("\"cardNumber\":\"************1234\"")
                .contains("\"id\":\"c-17\"")
                // an undeclared field in the payload is masked, not printed
                .doesNotContain("leaks without a default policy")
                // the raw values appear nowhere in the output
                .doesNotContain("123-45-6789")
                .doesNotContain("4111111111111234")
                .doesNotContain("super-secret-token")
                .doesNotContain("ada@example.com");
    }

    @Test
    void a_declared_header_is_redacted_and_a_sensitive_one_is_never_printed(CapturedOutput output)
            throws Exception {
        mockMvc.perform(post("/customers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Caller-Email", "grace@example.com")
                        .header("Authorization", "Bearer another-token")
                        .header("User-Agent", "integration-test")
                        .content("{\"id\":\"c-18\"}"))
                .andExpect(status().isOk());

        assertThat(output.getOut())
                .contains("X-Caller-Email=hmac:")            // policy from the classpath registry
                .contains("Authorization=***")               // always redacted
                .doesNotContain("grace@example.com")
                .doesNotContain("another-token");
    }

    @Test
    void the_response_is_still_delivered_intact(CapturedOutput output) throws Exception {
        String body = mockMvc.perform(post("/customers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"id\":\"c-19\",\"ssn\":\"999-99-9999\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // The API contract is untouched: the caller gets the real data back.
        assertThat(body).contains("999-99-9999");
        // The log does not.
        assertThat(output.getOut()).doesNotContain("999-99-9999");
    }

    @Test
    void a_body_whose_shape_is_unknown_is_summarised_rather_than_printed(CapturedOutput output)
            throws Exception {
        mockMvc.perform(post("/customers/notes")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("plain note with ssn 123-45-6789 inline"))
                .andExpect(status().isOk());

        assertThat(output.getOut())
                .contains("POST /customers/notes -> 200")
                .contains("<text/plain, ")
                .doesNotContain("123-45-6789");
    }

    @Test
    void a_form_body_is_redacted_field_by_field(CapturedOutput output) throws Exception {
        mockMvc.perform(post("/customers/form")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("id=c-20&ssn=123-45-6789"))
                .andExpect(status().isOk());

        assertThat(output.getOut())
                .contains("\"id\":\"c-20\"")
                .contains("\"ssn\":\"***\"")
                .doesNotContain("123-45-6789");
    }

    @Test
    void an_excluded_path_is_not_logged(CapturedOutput output) throws Exception {
        mockMvc.perform(post("/actuator/refresh").contentType(MediaType.APPLICATION_JSON).content("{}"));

        assertThat(output.getOut()).doesNotContain("POST /actuator/refresh");
    }

    @SpringBootApplication
    @RestController
    static class TestApplication {

        @PostMapping("/customers")
        Customer create(@RequestBody Customer customer) {
            return customer;
        }

        @PostMapping("/customers/notes")
        String note(@RequestBody String note) {
            return "stored";
        }

        @PostMapping("/customers/form")
        String form(@RequestParam("id") String id) {
            return "stored " + id;
        }

        @PostMapping("/actuator/refresh")
        String refresh() {
            return "ok";
        }
    }

    static class Customer {
        @LogPolicy(PolicyType.SAFE)
        public String id;

        @LogPolicy(PolicyType.MASK)
        public String ssn;

        @LogPolicy(value = PolicyType.PARTIAL, keep = 4)
        public String cardNumber;

        public String undocumented;
    }
}
