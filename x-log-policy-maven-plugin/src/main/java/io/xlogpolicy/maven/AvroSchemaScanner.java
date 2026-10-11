package io.xlogpolicy.maven;

import io.xlogpolicy.avro.AvroPolicies;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import org.apache.avro.AvroRuntimeException;
import org.apache.avro.Schema;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Reads {@code x-log-policy} out of Avro schema files ({@code .avsc}), producing the same
 * {@link SpecPolicyScanner.ScanResult} as the OpenAPI scanner so every goal treats both alike.
 *
 * <p>The files share one parser, in the order given, so a later file may refer to a named type defined
 * in an earlier one — the same rule {@code avro-maven-plugin} applies to its {@code imports}.
 */
public final class AvroSchemaScanner {

    private AvroSchemaScanner() {
    }

    /** Parses and scans the given {@code .avsc} files. */
    public static SpecPolicyScanner.ScanResult scan(List<File> files) {
        Schema.Parser parser = new Schema.Parser();
        List<Schema> roots = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        for (File file : files) {
            try {
                roots.add(parser.parse(file));
            } catch (IOException | AvroRuntimeException ex) {
                problems.add("could not parse " + file + ": " + ex.getMessage());
            }
        }
        return scan(roots, problems);
    }

    /** Scans already parsed schemas, including every record they reference. */
    public static SpecPolicyScanner.ScanResult scan(List<Schema> roots, List<String> problems) {
        LogPolicyMetadata.Builder metadata = LogPolicyMetadata.builder();
        List<SpecPolicyScanner.PropertyFinding> findings = new ArrayList<>();
        Set<Schema> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Schema root : roots) {
            walk(root, visited, metadata, findings, problems);
        }
        return new SpecPolicyScanner.ScanResult(metadata.build(), List.copyOf(findings), problems);
    }

    private static void walk(Schema schema, Set<Schema> visited, LogPolicyMetadata.Builder metadata,
                             List<SpecPolicyScanner.PropertyFinding> findings, List<String> problems) {
        switch (schema.getType()) {
            case UNION -> schema.getTypes().forEach(branch -> walk(branch, visited, metadata, findings, problems));
            case ARRAY -> walk(schema.getElementType(), visited, metadata, findings, problems);
            case MAP -> walk(schema.getValueType(), visited, metadata, findings, problems);
            case RECORD -> {
                if (visited.add(schema)) {
                    walkRecord(schema, visited, metadata, findings, problems);
                }
            }
            default -> {
            }
        }
    }

    private static void walkRecord(Schema record, Set<Schema> visited, LogPolicyMetadata.Builder metadata,
                                   List<SpecPolicyScanner.PropertyFinding> findings, List<String> problems) {
        // Indexed by simple name: that is the generated class's name, and what the runtime matches on.
        String recordName = record.getName();
        FieldPolicy recordDefault = read(() -> AvroPolicies.recordDefault(record), record.getFullName(), problems);
        for (Schema.Field field : record.getFields()) {
            String where = record.getFullName() + "." + field.name();
            FieldPolicy declared = read(() -> AvroPolicies.declared(field), where, problems);
            FieldPolicy effective = declared != null ? declared : recordDefault;
            findings.add(new SpecPolicyScanner.PropertyFinding(recordName, field.name(), effective, where,
                    AvroPolicies.isStructured(field.schema())));
            if (effective != null) {
                metadata.add(recordName, field.name(), effective);
            }
            walk(field.schema(), visited, metadata, findings, problems);
        }
    }

    private static FieldPolicy read(java.util.function.Supplier<Optional<FieldPolicy>> parse, String where,
                                    List<String> problems) {
        try {
            return parse.get().orElse(null);
        } catch (RuntimeException ex) {
            problems.add(where + ": " + ex.getMessage());
            return null;
        }
    }
}
