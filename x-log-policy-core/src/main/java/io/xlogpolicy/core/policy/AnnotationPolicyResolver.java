package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.LogPolicy;

import java.util.Optional;

/**
 * Reads {@link LogPolicy} from the property itself, then from its declaring type.
 */
public final class AnnotationPolicyResolver implements PolicyResolver {

    @Override
    public Optional<FieldPolicy> resolve(PropertyRef property) {
        LogPolicy annotation = property.onProperty();
        if (annotation == null) {
            annotation = property.onType();
        }
        return Optional.ofNullable(annotation).map(FieldPolicy::from);
    }

    @Override
    public Optional<FieldPolicy> resolveByFieldName(String propertyName) {
        return Optional.empty();
    }

    @Override
    public String sourceName() {
        return "@LogPolicy";
    }
}
