package io.xlogpolicy.demo;

import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.demo.model.Address;
import io.xlogpolicy.demo.model.Customer;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the build-time half of the contract: the annotations on the generated models came out of the
 * OpenAPI document, so the policy is visible in the code a developer reads — not only in a resource file.
 */
class GeneratedModelPolicyTest {

    @Test
    void the_generated_model_carries_the_policies_from_the_spec() throws Exception {
        assertThat(policyOn(Customer.class, "ssn").value()).isEqualTo(PolicyType.MASK);
        assertThat(policyOn(Customer.class, "email").value()).isEqualTo(PolicyType.HMAC);
        assertThat(policyOn(Customer.class, "id").value()).isEqualTo(PolicyType.SAFE);
        assertThat(policyOn(Customer.class, "internalNote").value()).isEqualTo(PolicyType.DROP);
    }

    @Test
    void parameters_from_the_object_form_survive_into_the_annotation() throws Exception {
        LogPolicy cardNumber = policyOn(Customer.class, "cardNumber");
        assertThat(cardNumber.value()).isEqualTo(PolicyType.PARTIAL);
        assertThat(cardNumber.keep()).isEqualTo(4);

        LogPolicy fullName = policyOn(Customer.class, "fullName");
        assertThat(fullName.value()).isEqualTo(PolicyType.CUSTOM);
        assertThat(fullName.name()).isEqualTo("initials");
    }

    @Test
    void a_referenced_schema_is_annotated_on_its_own_terms() throws Exception {
        assertThat(policyOn(Address.class, "street").value()).isEqualTo(PolicyType.MASK);
        assertThat(policyOn(Address.class, "city").value()).isEqualTo(PolicyType.SAFE);
        assertThat(policyOn(Address.class, "postalCode").keep()).isEqualTo(2);
    }

    @Test
    void a_property_that_points_at_another_schema_is_left_unannotated() throws Exception {
        // Address is descended into at runtime, so annotating the reference would mask the whole object.
        assertThat(Customer.class.getDeclaredField("address").getAnnotation(LogPolicy.class)).isNull();
    }

    private static LogPolicy policyOn(Class<?> type, String fieldName) throws NoSuchFieldException {
        Field field = type.getDeclaredField(fieldName);
        LogPolicy policy = field.getAnnotation(LogPolicy.class);
        assertThat(policy).as("@LogPolicy on %s.%s", type.getSimpleName(), fieldName).isNotNull();
        return policy;
    }
}
