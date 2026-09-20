package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.FieldPolicy;

import java.util.Optional;

/**
 * One source of policy information. Resolvers are consulted in order by {@link PolicyRegistry}; the
 * first non-empty answer wins.
 */
public interface PolicyResolver {

    /** @return the policy this source declares for {@code property}, or empty if it says nothing */
    Optional<FieldPolicy> resolve(PropertyRef property);

    /**
     * Resolves by property name alone, used for map keys and for free-form JSON where no declaring
     * type is available.
     */
    default Optional<FieldPolicy> resolveByFieldName(String propertyName) {
        return resolve(PropertyRef.ofFieldName(propertyName));
    }

    /** Human readable name, used in diagnostics. */
    default String sourceName() {
        return getClass().getSimpleName();
    }
}
