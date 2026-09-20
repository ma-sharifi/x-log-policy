package io.xlogpolicy.maven;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;
import com.github.javaparser.printer.lexicalpreservation.LexicalPreservingPrinter;
import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.LogPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.policy.MetadataPolicyResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Writes {@code @LogPolicy} onto the fields of generated model classes, so the policy is visible in the
 * code a developer reads and applies even if the runtime registry is missing.
 *
 * <p>Source rewriting is used rather than generator template overrides on purpose: a template override
 * pins the build to one openapi-generator version's internals, while this works with any generator (and
 * with hand-written sources) and can be re-run idempotently.
 *
 * <p>A class is matched to a schema by name, using the same rules as
 * {@link MetadataPolicyResolver#defaultSchemaNames(String)}, and a field to a property by its
 * {@code @JsonProperty} name when present, otherwise by its own name. Fields that already carry
 * {@code @LogPolicy} are left untouched.
 */
public final class SourceAnnotator {

    private final LogPolicyMetadata metadata;
    private final JavaParser parser;

    public SourceAnnotator(LogPolicyMetadata metadata) {
        this.metadata = metadata;
        this.parser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
    }

    /**
     * @param filesScanned   java files parsed
     * @param filesModified  java files rewritten
     * @param annotations    annotations inserted
     * @param problems       files that could not be parsed
     */
    public record Result(int filesScanned, int filesModified, int annotations, List<String> problems) {
    }

    /** Annotates every {@code .java} file under {@code root}. */
    public Result annotateTree(Path root, boolean dryRun) throws IOException {
        if (!Files.isDirectory(root)) {
            return new Result(0, 0, 0, List.of());
        }
        int scanned = 0;
        int modified = 0;
        int annotations = 0;
        List<String> problems = new ArrayList<>();

        List<Path> files;
        try (Stream<Path> walk = Files.walk(root)) {
            files = walk.filter(path -> path.toString().endsWith(".java")).sorted().toList();
        }
        for (Path file : files) {
            scanned++;
            String source = Files.readString(file, StandardCharsets.UTF_8);
            Rewrite rewrite;
            try {
                rewrite = annotate(source);
            } catch (RuntimeException ex) {
                problems.add(file + ": " + ex.getMessage());
                continue;
            }
            if (rewrite.count() == 0) {
                continue;
            }
            modified++;
            annotations += rewrite.count();
            if (!dryRun) {
                Files.writeString(file, rewrite.source(), StandardCharsets.UTF_8);
            }
        }
        return new Result(scanned, modified, annotations, problems);
    }

    /** @param source rewritten source, unchanged when {@code count} is zero */
    public record Rewrite(String source, int count) {
    }

    /** Annotates a single compilation unit. Exposed for tests. */
    public Rewrite annotate(String source) {
        ParseResult<CompilationUnit> parsed = parser.parse(source);
        if (!parsed.isSuccessful() || parsed.getResult().isEmpty()) {
            // JavaParser is error tolerant and hands back a partial tree; annotating one would produce
            // sources that no longer compile, so a file that did not parse cleanly is left untouched.
            String detail = parsed.getProblems().isEmpty() ? "unknown problem"
                    : parsed.getProblems().get(0).getVerboseMessage();
            throw new IllegalArgumentException("not parseable as Java: " + detail);
        }
        CompilationUnit unit = parsed.getResult().get();
        LexicalPreservingPrinter.setup(unit);

        int count = 0;
        for (TypeDeclaration<?> type : unit.getTypes()) {
            count += annotateType(type);
        }
        if (count == 0) {
            return new Rewrite(source, 0);
        }
        // The imports are added textually rather than through the AST: LexicalPreservingPrinter places a
        // synthesised import wherever it likes, including inside a preceding comment block, and generated
        // code is meant to stay readable.
        return new Rewrite(withImports(onOwnLine(LexicalPreservingPrinter.print(unit))), count);
    }

    /** A field declaration whose annotation the printer left in among the modifiers. */
    private static final java.util.regex.Pattern INLINE_ON_FIELD = java.util.regex.Pattern.compile(
            "^(\\s*)((?:(?:public|protected|private|static|final|transient|volatile)\\s+)*)"
                    + "(@LogPolicy\\([^()]*\\))\\s*(.*;)\\s*$");

    /**
     * Moves the annotation onto its own line above the field. JavaParser prints it after the modifiers,
     * which compiles but reads badly — and the point of stamping the annotation at all is that somebody
     * reading the model sees the policy.
     *
     * <p>Record components and parameters are left alone: there, inline is the only correct placement.
     */
    private static String onOwnLine(String source) {
        StringBuilder out = new StringBuilder(source.length() + 64);
        String newline = source.contains("\r\n") ? "\r\n" : "\n";
        boolean first = true;
        for (String line : source.split("\r?\n", -1)) {
            if (!first) {
                out.append(newline);
            }
            first = false;
            java.util.regex.Matcher matcher = INLINE_ON_FIELD.matcher(line);
            if (matcher.matches()) {
                out.append(matcher.group(1)).append(matcher.group(3)).append(newline)
                        .append(matcher.group(1)).append(matcher.group(2)).append(matcher.group(4));
            } else {
                out.append(line);
            }
        }
        return out.toString();
    }

    /** Adds the two imports after the last existing import, or after the package declaration. */
    private static String withImports(String source) {
        List<String> required = new ArrayList<>(2);
        for (String type : List.of(LogPolicy.class.getName(), PolicyType.class.getName())) {
            if (!source.contains("import " + type + ";")) {
                required.add("import " + type + ";");
            }
        }
        if (required.isEmpty()) {
            return source;
        }
        List<String> lines = new ArrayList<>(source.lines().toList());
        int insertAt = -1;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).stripLeading();
            if (line.startsWith("import ")) {
                insertAt = i + 1;
            } else if (insertAt < 0 && line.startsWith("package ")) {
                insertAt = i + 1;
            }
        }
        if (insertAt < 0) {
            insertAt = 0;
            lines.addAll(0, required);
        } else {
            lines.addAll(insertAt, required);
        }
        String rewritten = String.join(System.lineSeparator(), lines);
        return source.endsWith(System.lineSeparator()) || source.endsWith("\n")
                ? rewritten + System.lineSeparator() : rewritten;
    }

    private int annotateType(TypeDeclaration<?> type) {
        List<String> schemaNames = MetadataPolicyResolver.defaultSchemaNames(type.getNameAsString());
        int count = 0;

        for (FieldDeclaration field : type.getFields()) {
            if (field.isStatic() || field.getVariables().isEmpty()) {
                continue;
            }
            String property = propertyName(field, field.getVariable(0).getNameAsString());
            count += apply(field, schemaNames, property);
        }
        if (type instanceof RecordDeclaration record) {
            for (Parameter component : record.getParameters()) {
                String property = propertyName(component, component.getNameAsString());
                count += apply(component, schemaNames, property);
            }
        }
        // Generated models often nest enums and inner classes; give them their own chance to match.
        for (var member : type.getMembers()) {
            if (member instanceof TypeDeclaration<?> nested) {
                count += annotateType(nested);
            }
        }
        return count;
    }

    private int apply(NodeWithAnnotations<?> node, List<String> schemaNames, String property) {
        if (node.getAnnotationByName(LogPolicy.class.getSimpleName()).isPresent()) {
            return 0;
        }
        Optional<FieldPolicy> policy = find(schemaNames, property);
        if (policy.isEmpty()) {
            return 0;
        }
        node.addAnnotation(annotationFor(policy.get()));
        return 1;
    }

    private Optional<FieldPolicy> find(List<String> schemaNames, String property) {
        for (String schemaName : schemaNames) {
            Optional<FieldPolicy> found = metadata.find(schemaName, property);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    /** Reads the property name from {@code @JsonProperty}, falling back to the declared name. */
    private static String propertyName(NodeWithAnnotations<?> node, String declaredName) {
        for (AnnotationExpr annotation : node.getAnnotations()) {
            if (!annotation.getNameAsString().endsWith("JsonProperty")) {
                continue;
            }
            Optional<StringLiteralExpr> literal = annotation.findFirst(StringLiteralExpr.class);
            if (literal.isPresent()) {
                return literal.get().asString();
            }
        }
        return declaredName;
    }

    private AnnotationExpr annotationFor(FieldPolicy policy) {
        StringBuilder text = new StringBuilder("@LogPolicy(");
        boolean named = policy.keep() != FieldPolicy.KEEP_UNSET || !policy.customName().isBlank();
        text.append(named ? "value = " : "").append("PolicyType.").append(policy.type().name());
        if (policy.keep() != FieldPolicy.KEEP_UNSET) {
            text.append(", keep = ").append(policy.keep());
        }
        if (!policy.customName().isBlank()) {
            text.append(", name = \"").append(policy.customName().replace("\"", "\\\"")).append('"');
        }
        text.append(')');
        return parser.parseAnnotation(text.toString()).getResult()
                .orElseThrow(() -> new IllegalStateException("could not build annotation " + text));
    }
}
