package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the policy for a property by consulting its resolvers in order, and caches the outcome.
 *
 * <p>Precedence, highest first:
 * <ol>
 *   <li>configuration overrides ({@link OverridePolicyResolver})</li>
 *   <li>{@code @LogPolicy} on the property, then on its declaring type</li>
 *   <li>the build-time OpenAPI registry for the matching schema, then by property name</li>
 *   <li>the default policy — {@link PolicyType#MASK} unless configured otherwise</li>
 * </ol>
 *
 * <p>The default is applied by the caller rather than here, because it only applies to values that are
 * logged directly; a nested object with no policy of its own is descended into instead of being masked
 * wholesale. See {@code resolveExplicit} versus {@code resolve}.
 */
public final class PolicyRegistry {

    private static final FieldPolicy UNRESOLVED = new FieldPolicy(PolicyType.SAFE, -2, "", Map.of());

    private final List<PolicyResolver> resolvers;
    private final FieldPolicy defaultPolicy;
    private final ConcurrentHashMap<CacheKey, FieldPolicy> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, FieldPolicy> byNameCache = new ConcurrentHashMap<>();

    public PolicyRegistry(List<PolicyResolver> resolvers, FieldPolicy defaultPolicy) {
        this.resolvers = List.copyOf(resolvers);
        this.defaultPolicy = defaultPolicy == null ? FieldPolicy.of(PolicyType.MASK) : defaultPolicy;
    }

    /**
     * The standard chain: overrides, annotations, OpenAPI metadata.
     *
     * @param overrides     raw {@code Schema.property -> policy} overrides, may be {@code null}
     * @param metadata      build-time registry, may be {@link LogPolicyMetadata#empty()}
     * @param defaultPolicy policy for values nothing else covers; {@code MASK} keeps the starter fail-closed
     */
    public static PolicyRegistry standard(Map<String, String> overrides, LogPolicyMetadata metadata,
                                          FieldPolicy defaultPolicy) {
        List<PolicyResolver> resolvers = new ArrayList<>(3);
        resolvers.add(new OverridePolicyResolver(overrides));
        resolvers.add(new AnnotationPolicyResolver());
        resolvers.add(new MetadataPolicyResolver(metadata == null ? LogPolicyMetadata.empty() : metadata));
        return new PolicyRegistry(resolvers, defaultPolicy);
    }

    /** Annotations only — the registry you get when no OpenAPI metadata is on the classpath. */
    public static PolicyRegistry annotationsOnly(FieldPolicy defaultPolicy) {
        return new PolicyRegistry(List.of(new AnnotationPolicyResolver()), defaultPolicy);
    }

    /** @return the policy explicitly declared for the property, empty when nothing declares one */
    public Optional<FieldPolicy> resolveExplicit(PropertyRef property) {
        FieldPolicy cached = cache.computeIfAbsent(CacheKey.of(property), key -> {
            for (PolicyResolver resolver : resolvers) {
                Optional<FieldPolicy> resolved = resolver.resolve(property);
                if (resolved.isPresent()) {
                    return resolved.get();
                }
            }
            return UNRESOLVED;
        });
        return cached == UNRESOLVED ? Optional.empty() : Optional.of(cached);
    }

    /** @return the policy explicitly declared for a bare property name, e.g. a map key */
    public Optional<FieldPolicy> resolveExplicitByFieldName(String propertyName) {
        FieldPolicy cached = byNameCache.computeIfAbsent(propertyName, name -> {
            for (PolicyResolver resolver : resolvers) {
                Optional<FieldPolicy> resolved = resolver.resolveByFieldName(name);
                if (resolved.isPresent()) {
                    return resolved.get();
                }
            }
            return UNRESOLVED;
        });
        return cached == UNRESOLVED ? Optional.empty() : Optional.of(cached);
    }

    /** Explicit policy, or the configured default. */
    public FieldPolicy resolve(PropertyRef property) {
        return resolveExplicit(property).orElse(defaultPolicy);
    }

    /** Explicit policy for a bare property name, or the configured default. */
    public FieldPolicy resolveByFieldName(String propertyName) {
        return resolveExplicitByFieldName(propertyName).orElse(defaultPolicy);
    }

    public FieldPolicy defaultPolicy() {
        return defaultPolicy;
    }

    public List<PolicyResolver> resolvers() {
        return resolvers;
    }

    /** Explains where a policy came from. Intended for diagnostics, not for hot paths. */
    public String describe(PropertyRef property) {
        for (PolicyResolver resolver : resolvers) {
            Optional<FieldPolicy> resolved = resolver.resolve(property);
            if (resolved.isPresent()) {
                return resolved.get().type() + " (from " + resolver.sourceName() + ")";
            }
        }
        return defaultPolicy.type() + " (default)";
    }

    private record CacheKey(Class<?> owner, String name) {
        static CacheKey of(PropertyRef property) {
            return new CacheKey(property.owner(), property.name());
        }
    }
}
