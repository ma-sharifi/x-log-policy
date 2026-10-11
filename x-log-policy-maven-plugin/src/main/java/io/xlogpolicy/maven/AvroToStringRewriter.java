package io.xlogpolicy.maven;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.Position;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.type.ClassOrInterfaceType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Gives every Avro-generated record class a {@code toString()} that renders through
 * {@code AvroLogRedactor}, so the record is safe wherever it ends up in a log — an application's own
 * {@code log.info("{}", event)}, or a Kafka client or error handler logging the record it failed on.
 *
 * <p>The generated {@code toString()} is the one leak an explicit redactor call cannot cover, because the
 * code that calls it is not yours. The policy itself is not copied into the source: it is read at runtime
 * from the class's embedded schema, so the source and the schema cannot disagree.
 *
 * <p>Source rewriting rather than an {@code avro-maven-plugin} template override, for the reason given on
 * {@link SourceAnnotator}. Re-running is safe; a class that already declares its own {@code toString()}
 * is left alone and reported.
 */
public final class AvroToStringRewriter {

    static final String REDACTOR = "io.xlogpolicy.avro.AvroLogRedactor";

    /** Inserted as text, each line indented one level deeper than the class's closing brace. */
    private static final List<String> METHOD = List.of(
            "/**",
            " * Rendered with every field's x-log-policy applied; added by x-log-policy-maven-plugin.",
            " * Use {@code SpecificData.get().toString(this)} when the unredacted form is genuinely needed.",
            " */",
            "@Override",
            "public String toString() {",
            "  return " + REDACTOR + ".toSafeString(this);",
            "}");

    private final JavaParser parser = new JavaParser(new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));

    /**
     * @param filesScanned  java files parsed
     * @param filesModified java files rewritten
     * @param problems      files that could not be parsed, or records with a toString() of their own
     */
    public record Result(int filesScanned, int filesModified, List<String> problems) {
    }

    /** @param source rewritten source, unchanged when {@code count} is zero */
    public record Rewrite(String source, int count, List<String> skipped) {
    }

    /** Rewrites every {@code .java} file under {@code root}. */
    public Result rewriteTree(Path root, boolean dryRun) throws IOException {
        if (!Files.isDirectory(root)) {
            return new Result(0, 0, List.of());
        }
        List<Path> files;
        try (Stream<Path> walk = Files.walk(root)) {
            files = walk.filter(path -> path.toString().endsWith(".java")).sorted().toList();
        }
        int modified = 0;
        List<String> problems = new ArrayList<>();
        for (Path file : files) {
            Rewrite rewrite;
            try {
                rewrite = rewrite(Files.readString(file, StandardCharsets.UTF_8));
            } catch (RuntimeException ex) {
                problems.add(file + ": " + ex.getMessage());
                continue;
            }
            rewrite.skipped().forEach(name -> problems.add(file + ": " + name
                    + " declares its own toString(); left as is, so it is not redacted"));
            if (rewrite.count() == 0) {
                continue;
            }
            modified++;
            if (!dryRun) {
                Files.writeString(file, rewrite.source(), StandardCharsets.UTF_8);
            }
        }
        return new Result(files.size(), modified, problems);
    }

    /** Rewrites a single compilation unit. Exposed for tests. */
    public Rewrite rewrite(String source) {
        ParseResult<CompilationUnit> parsed = parser.parse(source);
        if (!parsed.isSuccessful() || parsed.getResult().isEmpty()) {
            String detail = parsed.getProblems().isEmpty() ? "unknown problem"
                    : parsed.getProblems().get(0).getVerboseMessage();
            throw new IllegalArgumentException("not parseable as Java: " + detail);
        }
        CompilationUnit unit = parsed.getResult().get();

        // The method is inserted as text before each class's closing brace: an AST printer would drop the
        // Javadoc and re-indent it, and generated code is meant to stay readable.
        List<Position> insertions = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (ClassOrInterfaceDeclaration type : unit.findAll(ClassOrInterfaceDeclaration.class)) {
            if (!isAvroRecord(type)) {
                continue;
            }
            List<MethodDeclaration> existing = type.getMethodsBySignature("toString");
            if (!existing.isEmpty()) {
                if (!existing.get(0).toString().contains(REDACTOR)) {
                    skipped.add(type.getNameAsString());
                }
                continue;
            }
            type.getEnd().ifPresent(insertions::add);
        }
        if (insertions.isEmpty()) {
            return new Rewrite(source, 0, skipped);
        }
        List<String> lines = new ArrayList<>(source.lines().toList());
        // Bottom-up, so an insertion never shifts a position still to be used.
        insertions.sort(Comparator.comparingInt((Position position) -> position.line).reversed());
        for (Position end : insertions) {
            int index = end.line - 1;
            String closing = lines.get(index);
            String before = closing.substring(0, end.column - 1);
            String indent = closing.substring(0, closing.length() - closing.stripLeading().length()) + "  ";
            List<String> method = new ArrayList<>();
            method.add("");
            METHOD.forEach(line -> method.add(indent + line));
            if (before.isBlank()) {
                lines.addAll(index, method);
            } else {
                // The closing brace shares its line with code: split it off.
                lines.set(index, before);
                method.add(closing.substring(end.column - 1));
                lines.addAll(index + 1, method);
            }
        }
        String newline = source.contains("\r\n") ? "\r\n" : "\n";
        String rewritten = String.join(newline, lines);
        return new Rewrite(source.endsWith("\n") ? rewritten + newline : rewritten, insertions.size(), skipped);
    }

    /** What avro-maven-plugin emits: {@code extends SpecificRecordBase implements SpecificRecord}. */
    private static boolean isAvroRecord(ClassOrInterfaceDeclaration type) {
        if (type.isInterface()) {
            return false;
        }
        for (ClassOrInterfaceType extended : type.getExtendedTypes()) {
            if (extended.getNameAsString().equals("SpecificRecordBase")) {
                return true;
            }
        }
        for (ClassOrInterfaceType implemented : type.getImplementedTypes()) {
            if (implemented.getNameAsString().equals("SpecificRecord")) {
                return true;
            }
        }
        return false;
    }
}
