package io.xlogpolicy.core;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares how a value must be treated when it reaches the logs.
 *
 * <p>This is the runtime counterpart of the {@code x-log-policy} OpenAPI extension: the
 * {@code x-log-policy-maven-plugin} stamps this annotation onto generated models and, for
 * hand-written types, the same information is picked up from the generated
 * {@code META-INF/x-log-policy.json} registry.
 *
 * <p>Placed on a type, it becomes the default for every property of that type.
 *
 * <pre>{@code
 * public class Customer {
 *     @LogPolicy(PolicyType.SAFE) private String id;
 *     @LogPolicy(PolicyType.MASK) private String ssn;
 *     @LogPolicy(value = PolicyType.PARTIAL, keep = 4) private String cardNumber;
 * }
 * }</pre>
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE,
        ElementType.RECORD_COMPONENT, ElementType.ANNOTATION_TYPE})
public @interface LogPolicy {

    /** The policy to apply. */
    PolicyType value();

    /**
     * Number of trailing characters preserved by {@link PolicyType#PARTIAL}.
     * {@code -1} means "use the configured default".
     */
    int keep() default -1;

    /** Name of the {@code ValueRedaction} to use when {@link #value()} is {@link PolicyType#CUSTOM}. */
    String name() default "";
}
