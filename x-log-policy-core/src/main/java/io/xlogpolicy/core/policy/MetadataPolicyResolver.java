package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Resolves policies from the build-time registry generated out of the OpenAPI document.
 *
 * <p>A Java type is matched to a schema by name. By default the class simple name is tried, then the
 * same name with a common generator suffix stripped ({@code CustomerDto} → {@code Customer}). Supply a
 * different {@code schemaNamer} if your generator uses another convention.
 */
public final class MetadataPolicyResolver implements PolicyResolver {

    private static final List<String> SUFFIXES = List.of("Dto", "DTO", "Model", "Resource", "Representation");

    private final LogPolicyMetadata metadata;
    private final Function<Class<?>, List<String>> schemaNamer;

    public MetadataPolicyResolver(LogPolicyMetadata metadata) {
        this(metadata, MetadataPolicyResolver::defaultSchemaNames);
    }

    public MetadataPolicyResolver(LogPolicyMetadata metadata, Function<Class<?>, List<String>> schemaNamer) {
        this.metadata = metadata;
        this.schemaNamer = schemaNamer;
    }

    @Override
    public Optional<FieldPolicy> resolve(PropertyRef property) {
        if (property.hasOwner()) {
            for (String schemaName : schemaNamer.apply(property.owner())) {
                Optional<FieldPolicy> found = metadata.find(schemaName, property.name());
                if (found.isEmpty() && !property.implicitName().equals(property.name())) {
                    found = metadata.find(schemaName, property.implicitName());
                }
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return resolveByFieldName(property.name())
                .or(() -> resolveByFieldName(property.implicitName()));
    }

    @Override
    public Optional<FieldPolicy> resolveByFieldName(String propertyName) {
        return metadata.findByFieldName(propertyName);
    }

    public LogPolicyMetadata metadata() {
        return metadata;
    }

    @Override
    public String sourceName() {
        return "openapi-metadata";
    }

    /** Schema names to try for a Java type, in order. Shared with the build-time annotator so
     * that compile time and runtime agree on which schema a class belongs to. */
    public static List<String> defaultSchemaNames(Class<?> type) {
        return defaultSchemaNames(type.getSimpleName());
    }

    /** Schema names to try for a simple type name, in order. */
    public static List<String> defaultSchemaNames(String simpleName) {
        List<String> names = new ArrayList<>(2);
        names.add(simpleName);
        for (String suffix : SUFFIXES) {
            if (simpleName.length() > suffix.length() && simpleName.endsWith(suffix)) {
                names.add(simpleName.substring(0, simpleName.length() - suffix.length()));
                break;
            }
        }
        return names;
    }
}
