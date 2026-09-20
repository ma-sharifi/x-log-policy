package io.xlogpolicy.maven;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class SourceAnnotatorTest {

    private static final LogPolicyMetadata METADATA = LogPolicyMetadata.builder()
            .add("Customer", "ssn", FieldPolicy.of(PolicyType.MASK))
            .add("Customer", "cardNumber", FieldPolicy.partial(4))
            .add("Customer", "loyaltyId", FieldPolicy.custom("loyalty"))
            .add("Customer", "social_security_number", FieldPolicy.of(PolicyType.MASK))
            .add("Customer", "id", FieldPolicy.of(PolicyType.SAFE))
            .build();

    private final SourceAnnotator annotator = new SourceAnnotator(METADATA);

    @Test
    void a_field_gets_the_policy_declared_in_the_spec() {
        String source = """
                package io.example.model;

                public class Customer {
                    private String id;
                    private String ssn;
                    private String cardNumber;
                    private String loyaltyId;
                    private String unrelated;
                }
                """;

        SourceAnnotator.Rewrite rewrite = annotator.annotate(source);

        assertThat(rewrite.count()).isEqualTo(4);
        assertThat(rewrite.source())
                .contains("import io.xlogpolicy.core.LogPolicy;")
                .contains("import io.xlogpolicy.core.PolicyType;")
                .contains("@LogPolicy(PolicyType.SAFE)")
                .contains("@LogPolicy(PolicyType.MASK)")
                .contains("@LogPolicy(value = PolicyType.PARTIAL, keep = 4)")
                .contains("@LogPolicy(value = PolicyType.CUSTOM, name = \"loyalty\")");
        // A property the spec says nothing about is left bare; the runtime default covers it.
        assertThat(rewrite.source()).contains("private String unrelated;");
    }

    @Test
    void the_annotation_is_placed_on_its_own_line_above_the_field() {
        String source = """
                package io.example.model;

                public class Customer {
                    private String ssn;
                    private final String cardNumber = null;
                }
                """;

        assertThat(annotator.annotate(source).source())
                .contains("    @LogPolicy(PolicyType.MASK)\n    private String ssn;")
                .contains("    @LogPolicy(value = PolicyType.PARTIAL, keep = 4)\n"
                        + "    private final String cardNumber = null;");
    }

    @Test
    void an_annotation_already_carried_by_the_generated_source_is_kept_inline_where_it_belongs() {
        // A record component cannot take the annotation on a line of its own.
        String source = """
                package io.example.model;

                public record Customer(String ssn) {
                }
                """;

        assertThat(annotator.annotate(source).source()).contains("(@LogPolicy(PolicyType.MASK) String ssn)");
    }

    @Test
    void a_renamed_property_is_matched_through_json_property() {
        String source = """
                package io.example.model;

                import com.fasterxml.jackson.annotation.JsonProperty;

                public class Customer {
                    @JsonProperty("social_security_number")
                    private String socialSecurityNumber;
                }
                """;

        assertThat(annotator.annotate(source).source())
                .contains("@JsonProperty(\"social_security_number\")")
                .contains("@LogPolicy(PolicyType.MASK)");
    }

    @Test
    void a_class_with_a_generator_suffix_still_matches_its_schema() {
        String source = """
                package io.example.model;

                public class CustomerDto {
                    private String ssn;
                }
                """;

        assertThat(annotator.annotate(source).count()).isEqualTo(1);
    }

    @Test
    void records_are_annotated_on_their_components() {
        String source = """
                package io.example.model;

                public record Customer(String id, String ssn) {
                }
                """;

        assertThat(annotator.annotate(source).source())
                .contains("@LogPolicy(PolicyType.SAFE) String id")
                .contains("@LogPolicy(PolicyType.MASK) String ssn");
    }

    @Test
    void running_twice_changes_nothing_the_second_time() {
        String once = annotator.annotate("""
                package io.example.model;

                public class Customer {
                    private String ssn;
                }
                """).source();

        SourceAnnotator.Rewrite twice = annotator.annotate(once);

        assertThat(twice.count()).isZero();
        assertThat(twice.source()).isEqualTo(once);
    }

    @Test
    void an_existing_policy_is_never_overwritten() {
        String source = """
                package io.example.model;

                import io.xlogpolicy.core.LogPolicy;
                import io.xlogpolicy.core.PolicyType;

                public class Customer {
                    @LogPolicy(PolicyType.DROP)
                    private String ssn;
                }
                """;

        assertThat(annotator.annotate(source).count()).isZero();
    }

    @Test
    void static_fields_are_ignored() {
        String source = """
                package io.example.model;

                public class Customer {
                    public static final String ssn = "not a property";
                }
                """;

        assertThat(annotator.annotate(source).count()).isZero();
    }

    @Test
    void formatting_outside_the_annotated_lines_is_preserved() {
        String source = """
                package io.example.model;

                /** Doc comment that must survive. */
                public class Customer {

                    // a deliberate blank line and comment above the field
                    private String ssn;
                }
                """;

        assertThat(annotator.annotate(source).source())
                .contains("/** Doc comment that must survive. */")
                .contains("// a deliberate blank line and comment above the field");
    }

    @Test
    void a_source_tree_is_rewritten_in_place(@TempDir Path root) throws IOException {
        Path model = root.resolve("io/example/model");
        Files.createDirectories(model);
        Files.writeString(model.resolve("Customer.java"), """
                package io.example.model;

                public class Customer {
                    private String ssn;
                }
                """);
        Files.writeString(model.resolve("NotAModel.java"), """
                package io.example.model;

                public class NotAModel {
                    private String whatever;
                }
                """);

        SourceAnnotator.Result result = annotator.annotateTree(root, false);

        assertThat(result.filesScanned()).isEqualTo(2);
        assertThat(result.filesModified()).isEqualTo(1);
        assertThat(result.annotations()).isEqualTo(1);
        assertThat(Files.readString(model.resolve("Customer.java"))).contains("@LogPolicy(PolicyType.MASK)");
        assertThat(Files.readString(model.resolve("NotAModel.java"))).doesNotContain("LogPolicy");
    }

    @Test
    void a_dry_run_writes_nothing(@TempDir Path root) throws IOException {
        Path file = root.resolve("Customer.java");
        String original = """
                public class Customer {
                    private String ssn;
                }
                """;
        Files.writeString(file, original);

        SourceAnnotator.Result result = annotator.annotateTree(root, true);

        assertThat(result.annotations()).isEqualTo(1);
        assertThat(Files.readString(file)).isEqualTo(original);
    }

    @Test
    void an_unparseable_file_is_reported_and_skipped(@TempDir Path root) throws IOException {
        Files.writeString(root.resolve("Broken.java"), "this is not java {{{");

        SourceAnnotator.Result result = annotator.annotateTree(root, false);

        assertThat(result.problems()).hasSize(1);
        assertThat(result.annotations()).isZero();
    }
}
