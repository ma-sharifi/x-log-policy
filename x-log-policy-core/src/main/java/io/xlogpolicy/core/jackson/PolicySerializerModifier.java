package io.xlogpolicy.core.jackson;

import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.introspect.AnnotatedField;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.policy.PolicyRegistry;
import io.xlogpolicy.core.policy.PropertyRef;
import io.xlogpolicy.core.redaction.RedactionEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Rewrites every bean property according to its resolved policy.
 *
 * <p>The decision per property:
 * <ul>
 *   <li>{@code DROP} — the property is removed from the output;</li>
 *   <li>any other explicit policy — a {@link RedactingSerializer} replaces the value;</li>
 *   <li>no explicit policy and a value-like type — the default policy applies (fail-closed);</li>
 *   <li>no explicit policy and a structured type — the property is left alone, so the nested bean's own
 *       properties are resolved when Jackson descends into it;</li>
 *   <li>free-form maps — a {@link MapPolicySerializer} resolves each key by name.</li>
 * </ul>
 *
 * <p>An explicit policy overrides a {@code @JsonSerialize} serializer on the same property. That is
 * deliberate: a custom renderer must not be able to reintroduce a value the contract says to hide.
 */
final class PolicySerializerModifier extends BeanSerializerModifier {

    private static final long serialVersionUID = 1L;

    private final transient PolicyRegistry registry;
    private final transient RedactionEngine engine;

    PolicySerializerModifier(PolicyRegistry registry, RedactionEngine engine) {
        this.registry = registry;
        this.engine = engine;
    }

    @Override
    public List<BeanPropertyWriter> changeProperties(SerializationConfig config, BeanDescription beanDesc,
                                                     List<BeanPropertyWriter> beanProperties) {
        Class<?> beanClass = beanDesc.getBeanClass();
        LogPolicy typeAnnotation = beanClass.getAnnotation(LogPolicy.class);
        List<BeanPropertyWriter> result = new ArrayList<>(beanProperties.size());

        for (BeanPropertyWriter writer : beanProperties) {
            PropertyRef ref = new PropertyRef(beanClass, writer.getName(), implicitName(writer),
                    writer.getAnnotation(LogPolicy.class), typeAnnotation);
            Optional<FieldPolicy> explicit = registry.resolveExplicit(ref);
            JavaType type = writer.getType();

            FieldPolicy policy = explicit.orElseGet(() -> ValueTypes.isValueLike(type)
                    ? registry.defaultPolicy()
                    : FieldPolicy.of(PolicyType.SAFE));

            if (policy.isDrop()) {
                continue;
            }
            JsonSerializer<Object> replacement = serializerFor(policy, type, explicit.isPresent());
            if (replacement != null) {
                writer.assignSerializer(replacement);
            }
            result.add(writer);
        }
        return result;
    }

    private JsonSerializer<Object> serializerFor(FieldPolicy policy, JavaType type, boolean explicit) {
        if (!policy.isSafe()) {
            return new RedactingSerializer(engine, policy);
        }
        if (type != null && type.isMapLikeType()) {
            // Map keys are data, so they are resolved by name. An explicitly safe map keeps its values,
            // except for keys the contract policies elsewhere.
            return new MapPolicySerializer(registry, engine, explicit ? FieldPolicy.of(PolicyType.SAFE) : null);
        }
        if (ValueTypes.isTextLike(type) && engine.settings().maxStringLength() > 0) {
            return new TruncatingStringSerializer(engine);
        }
        return null;
    }

    /** The underlying field or accessor name, which is what the OpenAPI schema is keyed by. */
    private static String implicitName(BeanPropertyWriter writer) {
        AnnotatedMember member = writer.getMember();
        if (member instanceof AnnotatedField field) {
            return field.getName();
        }
        if (member instanceof AnnotatedMethod method) {
            String name = method.getName();
            if (name.startsWith("get") && name.length() > 3) {
                return decapitalize(name.substring(3));
            }
            if (name.startsWith("is") && name.length() > 2) {
                return decapitalize(name.substring(2));
            }
            return name;
        }
        return writer.getName();
    }

    private static String decapitalize(String name) {
        if (name.length() > 1 && Character.isUpperCase(name.charAt(1))) {
            return name;
        }
        return Character.toLowerCase(name.charAt(0)) + name.substring(1);
    }
}
