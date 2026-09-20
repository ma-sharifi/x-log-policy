package io.xlogpolicy.maven;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;

import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Reads {@code x-log-policy} out of an OpenAPI document.
 *
 * <p>Deliberately free of any Maven type so it can be unit-tested against fixture documents; the mojos
 * are thin wrappers around it.
 *
 * <p>What is walked: {@code components.schemas} (including {@code allOf}/{@code anyOf}/{@code oneOf},
 * arrays, inline objects and {@code additionalProperties}), inline request and response schemas, and
 * parameters and headers. A policy declared on a schema applies to every property of that schema unless
 * the property declares its own.
 */
public final class SpecPolicyScanner {

    /** Extension key, matched case-insensitively because tooling likes to rewrite casing. */
    public static final String EXTENSION = "x-log-policy";

    /** Synthetic schema name under which parameter and header policies are recorded. */
    public static final String PARAMETERS_SCHEMA = "#parameters";

    private SpecPolicyScanner() {
    }

    /**
     * Where a property was seen, and what (if anything) it declared.
     *
     * @param structured whether the property holds another object (a {@code $ref}, an inline object, a
     *                   composition, or an array or map of those). Such a property needs no policy of its
     *                   own: at runtime it is descended into so the nested fields keep their own policies.
     */
    public record PropertyFinding(String schemaName, String propertyName, FieldPolicy policy, String location,
                                  boolean structured) {

        public boolean hasPolicy() {
            return policy != null;
        }

        /** A leaf value is what a policy has to cover, and what the validator checks. */
        public boolean needsPolicy() {
            return policy == null && !structured;
        }
    }

    /**
     * @param metadata registry to write to {@code META-INF/x-log-policy.json}
     * @param findings every property seen, whether or not it declared a policy
     * @param problems parse messages and invalid policy declarations
     */
    public record ScanResult(LogPolicyMetadata metadata, List<PropertyFinding> findings, List<String> problems) {

        public long policiedCount() {
            return findings.stream().filter(PropertyFinding::hasPolicy).count();
        }
    }

    /** Parses and scans one document. */
    public static ScanResult scan(String location) {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(false);
        options.setResolveCombinators(false);

        SwaggerParseResult parsed = new OpenAPIV3Parser().readLocation(location, null, options);
        List<String> problems = new ArrayList<>();
        if (parsed.getMessages() != null) {
            problems.addAll(parsed.getMessages());
        }
        OpenAPI api = parsed.getOpenAPI();
        if (api == null) {
            problems.add("could not parse " + location);
            return new ScanResult(LogPolicyMetadata.empty(), List.of(), problems);
        }
        return scan(api, problems);
    }

    /** Scans an already parsed document. */
    public static ScanResult scan(OpenAPI api, List<String> problems) {
        Walker walker = new Walker(problems);
        if (api.getComponents() != null && api.getComponents().getSchemas() != null) {
            // Claim the named schemas first: a schema that has a name must never be indexed under a
            // synthetic one just because some property or request body happens to reference it.
            walker.claimNames(api.getComponents().getSchemas());
            api.getComponents().getSchemas().forEach(walker::walkNamedSchema);
        }
        if (api.getComponents() != null && api.getComponents().getParameters() != null) {
            api.getComponents().getParameters().values().forEach(walker::walkParameter);
        }
        if (api.getComponents() != null && api.getComponents().getHeaders() != null) {
            api.getComponents().getHeaders().forEach(walker::walkHeader);
        }
        if (api.getPaths() != null) {
            api.getPaths().forEach(walker::walkPath);
        }
        return new ScanResult(walker.metadata.build(), List.copyOf(walker.findings), problems);
    }

    /** Reads the extension off a schema, header or parameter. Returns {@code null} when absent. */
    static FieldPolicy readPolicy(Map<String, Object> extensions, String where, List<String> problems) {
        if (extensions == null || extensions.isEmpty()) {
            return null;
        }
        Object raw = null;
        for (Map.Entry<String, Object> entry : extensions.entrySet()) {
            if (entry.getKey() != null && entry.getKey().toLowerCase(Locale.ROOT).equals(EXTENSION)) {
                raw = entry.getValue();
                break;
            }
        }
        if (raw == null) {
            return null;
        }
        try {
            return parsePolicy(raw);
        } catch (RuntimeException ex) {
            problems.add(where + ": " + ex.getMessage());
            return null;
        }
    }

    private static FieldPolicy parsePolicy(Object raw) {
        if (raw instanceof String text) {
            return FieldPolicy.of(PolicyType.parse(text));
        }
        if (raw instanceof Map<?, ?> map) {
            Object policy = firstOf(map, "policy", "value", "type");
            if (policy == null) {
                throw new IllegalArgumentException(EXTENSION + " object form requires a 'policy' entry");
            }
            PolicyType type = PolicyType.parse(String.valueOf(policy));
            int keep = FieldPolicy.KEEP_UNSET;
            Object keepValue = firstOf(map, "keep", "keepLast", "visible");
            if (keepValue != null) {
                try {
                    keep = Integer.parseInt(String.valueOf(keepValue).trim());
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException(EXTENSION + " 'keep' must be a number, got " + keepValue);
                }
                if (keep < 0) {
                    throw new IllegalArgumentException(EXTENSION + " 'keep' must not be negative");
                }
            }
            String name = String.valueOf(firstOf(map, "name", "redaction") == null
                    ? "" : firstOf(map, "name", "redaction"));
            Object params = map.get("params");
            @SuppressWarnings("unchecked")
            Map<String, Object> extra = params instanceof Map ? (Map<String, Object>) params : Map.of();
            return new FieldPolicy(type, keep, name, extra);
        }
        throw new IllegalArgumentException(EXTENSION + " must be a policy name or an object, got "
                + raw.getClass().getSimpleName());
    }

    private static Object firstOf(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String capitalize(String value) {
        return value.isEmpty() ? value : Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    /** Recursive walk with cycle protection; schemas can reference each other freely. */
    private static final class Walker {

        private final LogPolicyMetadata.Builder metadata = LogPolicyMetadata.builder();
        private final List<PropertyFinding> findings = new ArrayList<>();
        private final List<String> problems;
        private final Set<Schema<?>> visited = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        private final Map<Schema<?>, String> nameOf = new IdentityHashMap<>();

        Walker(List<String> problems) {
            this.problems = problems;
        }

        void claimNames(Map<String, Schema> schemas) {
            schemas.forEach((name, schema) -> nameOf.put(schema, name));
        }

        void walkNamedSchema(String schemaName, Schema<?> schema) {
            walkObject(schemaName, schema, null);
        }

        /**
         * @param inherited policy declared on the schema itself, applied to properties that declare none
         */
        private void walkObject(String schemaName, Schema<?> schema, FieldPolicy inherited) {
            if (schema == null) {
                return;
            }
            String claimedName = nameOf.get(schema);
            if (claimedName != null && !claimedName.equals(schemaName)) {
                return;
            }
            if (!visited.add(schema)) {
                return;
            }
            FieldPolicy schemaPolicy = readPolicy(schema.getExtensions(), schemaName, problems);
            FieldPolicy effectiveInherited = schemaPolicy != null ? schemaPolicy : inherited;

            walkComposed(schemaName, schema.getAllOf(), effectiveInherited);
            walkComposed(schemaName, schema.getAnyOf(), effectiveInherited);
            walkComposed(schemaName, schema.getOneOf(), effectiveInherited);

            Map<String, Schema> properties = schema.getProperties();
            if (properties == null) {
                return;
            }
            properties.forEach((propertyName, property) -> {
                String where = schemaName + "." + propertyName;
                FieldPolicy declared = readPolicy(property.getExtensions(), where, problems);
                if (declared == null) {
                    declared = policyFromContainer(property, where);
                }
                FieldPolicy effective = declared != null ? declared : effectiveInherited;

                findings.add(new PropertyFinding(schemaName, propertyName, effective, where,
                        isStructured(property)));
                if (effective != null) {
                    metadata.add(schemaName, propertyName, effective);
                }
                // Inline objects become their own class in every generator; index them under the name
                // openapi-generator would give them, so the runtime can match either.
                Schema<?> nested = unwrap(property);
                if (nested != null && nested.getProperties() != null) {
                    walkObject(schemaName + capitalize(propertyName), nested, null);
                }
            });
        }

        private void walkComposed(String schemaName, List<? extends Schema> parts, FieldPolicy inherited) {
            if (parts == null) {
                return;
            }
            for (Schema<?> part : parts) {
                walkObject(schemaName, part, inherited);
            }
        }

        /**
         * A policy on an array's {@code items} or on a map's {@code additionalProperties} describes the
         * contained values, which is the same thing as the property itself being policied: every element
         * is redacted.
         */
        private FieldPolicy policyFromContainer(Schema<?> property, String where) {
            if (property.getItems() != null) {
                FieldPolicy items = readPolicy(property.getItems().getExtensions(), where + "[]", problems);
                if (items != null) {
                    return items;
                }
            }
            if (property.getAdditionalProperties() instanceof Schema<?> additional) {
                return readPolicy(additional.getExtensions(), where + ".additionalProperties", problems);
            }
            return null;
        }

        /**
         * Whether this property points at another object rather than holding a value. Such properties are
         * walked, not policied.
         */
        private boolean isStructured(Schema<?> property) {
            if (property.get$ref() != null) {
                return true;
            }
            if (property.getProperties() != null && !property.getProperties().isEmpty()) {
                return true;
            }
            if (property.getAllOf() != null || property.getAnyOf() != null || property.getOneOf() != null) {
                return true;
            }
            if (property.getItems() != null) {
                return isStructured(property.getItems());
            }
            if (property.getAdditionalProperties() instanceof Schema<?> additional) {
                return isStructured(additional);
            }
            return false;
        }

        private Schema<?> unwrap(Schema<?> property) {
            if (property.getItems() != null) {
                return property.getItems();
            }
            if (property.getAdditionalProperties() instanceof Schema<?> additional) {
                return additional;
            }
            return property;
        }

        void walkPath(String path, PathItem item) {
            if (item == null) {
                return;
            }
            if (item.getParameters() != null) {
                item.getParameters().forEach(this::walkParameter);
            }
            for (Operation operation : item.readOperations()) {
                String hint = operation.getOperationId() != null ? capitalize(operation.getOperationId())
                        : sanitize(path);
                if (operation.getParameters() != null) {
                    operation.getParameters().forEach(this::walkParameter);
                }
                if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
                    walkContent(hint + "Request", operation.getRequestBody().getContent().values());
                }
                if (operation.getResponses() != null) {
                    for (Map.Entry<String, ApiResponse> response : operation.getResponses().entrySet()) {
                        ApiResponse value = response.getValue();
                        if (value == null) {
                            continue;
                        }
                        if (value.getContent() != null) {
                            walkContent(hint + "Response", value.getContent().values());
                        }
                        if (value.getHeaders() != null) {
                            value.getHeaders().forEach(this::walkHeader);
                        }
                    }
                }
            }
        }

        private void walkContent(String nameHint, Collection<MediaType> content) {
            for (MediaType mediaType : content) {
                if (mediaType != null && mediaType.getSchema() != null) {
                    walkObject(nameHint, mediaType.getSchema(), null);
                }
            }
        }

        void walkParameter(Parameter parameter) {
            if (parameter == null || parameter.getName() == null) {
                return;
            }
            String where = "parameter " + parameter.getName();
            FieldPolicy policy = readPolicy(parameter.getExtensions(), where, problems);
            if (policy == null && parameter.getSchema() != null) {
                policy = readPolicy(parameter.getSchema().getExtensions(), where, problems);
            }
            findings.add(new PropertyFinding(PARAMETERS_SCHEMA, parameter.getName(), policy, where, false));
            if (policy != null) {
                metadata.add(PARAMETERS_SCHEMA, parameter.getName(), policy);
            }
        }

        void walkHeader(String name, Header header) {
            if (header == null) {
                return;
            }
            String where = "header " + name;
            FieldPolicy policy = readPolicy(header.getExtensions(), where, problems);
            if (policy == null && header.getSchema() != null) {
                policy = readPolicy(header.getSchema().getExtensions(), where, problems);
            }
            findings.add(new PropertyFinding(PARAMETERS_SCHEMA, name, policy, where, false));
            if (policy != null) {
                metadata.add(PARAMETERS_SCHEMA, name, policy);
            }
        }

        private String sanitize(String path) {
            Set<String> parts = new LinkedHashSet<>();
            for (String part : path.split("[^A-Za-z0-9]+")) {
                if (!part.isEmpty()) {
                    parts.add(capitalize(part));
                }
            }
            return String.join("", parts);
        }
    }
}
