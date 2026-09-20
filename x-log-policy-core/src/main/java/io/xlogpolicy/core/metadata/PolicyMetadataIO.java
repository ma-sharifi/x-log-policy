package io.xlogpolicy.core.metadata;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Reads and writes {@link LogPolicyMetadata} in its JSON form:
 *
 * <pre>{@code
 * {
 *   "version": 1,
 *   "schemas":     { "Customer": { "ssn": { "policy": "MASK" } } },
 *   "byFieldName": { "ssn": { "policy": "MASK" } }
 * }
 * }</pre>
 */
public final class PolicyMetadataIO {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PolicyMetadataIO() {
    }

    public static void write(LogPolicyMetadata metadata, OutputStream out) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", LogPolicyMetadata.FORMAT_VERSION);

        ObjectNode schemas = root.putObject("schemas");
        metadata.schemas().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(schema -> {
                    ObjectNode properties = schemas.putObject(schema.getKey());
                    schema.getValue().entrySet().stream()
                            .sorted(Map.Entry.comparingByKey())
                            .forEach(property -> properties.set(property.getKey(), toNode(property.getValue())));
                });

        ObjectNode byFieldName = root.putObject("byFieldName");
        metadata.byFieldName().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> byFieldName.set(entry.getKey(), toNode(entry.getValue())));

        MAPPER.writerWithDefaultPrettyPrinter().writeValue(out, root);
    }

    public static String writeToString(LogPolicyMetadata metadata) {
        try (var out = new java.io.ByteArrayOutputStream()) {
            write(metadata, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    public static LogPolicyMetadata read(InputStream in) throws IOException {
        JsonNode root = MAPPER.readTree(in);
        if (root == null || root.isNull()) {
            return LogPolicyMetadata.empty();
        }
        int version = root.path("version").asInt(LogPolicyMetadata.FORMAT_VERSION);
        if (version > LogPolicyMetadata.FORMAT_VERSION) {
            throw new IOException("x-log-policy metadata version " + version
                    + " is newer than supported version " + LogPolicyMetadata.FORMAT_VERSION
                    + "; upgrade x-log-policy-core");
        }
        LogPolicyMetadata.Builder builder = LogPolicyMetadata.builder();
        JsonNode schemas = root.path("schemas");
        Iterator<String> schemaNames = schemas.fieldNames();
        while (schemaNames.hasNext()) {
            String schemaName = schemaNames.next();
            JsonNode properties = schemas.get(schemaName);
            Iterator<String> propertyNames = properties.fieldNames();
            while (propertyNames.hasNext()) {
                String propertyName = propertyNames.next();
                builder.add(schemaName, propertyName, fromNode(properties.get(propertyName)));
            }
        }
        return builder.build();
    }

    public static LogPolicyMetadata readFromString(String json) {
        try (var in = new java.io.ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8))) {
            return read(in);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Loads and merges every {@value LogPolicyMetadata#RESOURCE_PATH} visible to the class loader, so
     * policies contributed by several jars all take effect. Unreadable resources are skipped rather
     * than failing application startup; the caller decides whether to warn.
     */
    public static LogPolicyMetadata loadAll(ClassLoader classLoader, List<String> problems) {
        LogPolicyMetadata merged = LogPolicyMetadata.empty();
        for (URL url : resources(classLoader, problems)) {
            try (InputStream in = url.openStream()) {
                merged = merged.merge(read(in));
            } catch (IOException | RuntimeException ex) {
                problems.add(url + ": " + ex.getMessage());
            }
        }
        return merged;
    }

    private static List<URL> resources(ClassLoader classLoader, List<String> problems) {
        List<URL> urls = new ArrayList<>();
        try {
            Enumeration<URL> found = classLoader.getResources(LogPolicyMetadata.RESOURCE_PATH);
            while (found.hasMoreElements()) {
                urls.add(found.nextElement());
            }
        } catch (IOException ex) {
            problems.add("classpath scan for " + LogPolicyMetadata.RESOURCE_PATH + " failed: " + ex.getMessage());
        }
        return urls;
    }

    private static JsonNode toNode(FieldPolicy policy) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("policy", policy.type().name());
        if (policy.keep() != FieldPolicy.KEEP_UNSET) {
            node.put("keep", policy.keep());
        }
        if (!policy.customName().isBlank()) {
            node.put("name", policy.customName());
        }
        if (!policy.params().isEmpty()) {
            node.set("params", MAPPER.valueToTree(policy.params()));
        }
        return node;
    }

    private static FieldPolicy fromNode(JsonNode node) {
        if (node.isTextual()) {
            return FieldPolicy.of(PolicyType.parse(node.asText()));
        }
        PolicyType type = PolicyType.parse(node.path("policy").asText());
        int keep = node.path("keep").asInt(FieldPolicy.KEEP_UNSET);
        String name = node.path("name").asText("");
        Map<String, Object> params = node.has("params")
                ? MAPPER.convertValue(node.get("params"), MAPPER.getTypeFactory()
                        .constructMapType(java.util.LinkedHashMap.class, String.class, Object.class))
                : Map.of();
        return new FieldPolicy(type, keep, name, params);
    }
}
