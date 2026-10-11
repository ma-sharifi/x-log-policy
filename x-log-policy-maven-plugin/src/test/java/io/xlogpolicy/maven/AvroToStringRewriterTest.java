package io.xlogpolicy.maven;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AvroToStringRewriterTest {

    private static final String GENERATED = """
            package com.example.events;

            /** Avro generated. */
            @org.apache.avro.specific.AvroGenerated
            public class CustomerCreated extends org.apache.avro.specific.SpecificRecordBase
                    implements org.apache.avro.specific.SpecificRecord {
              private java.lang.CharSequence id;

              public java.lang.Object get(int field$) {
                return id;
              }

              public static class Builder extends org.apache.avro.specific.SpecificRecordBuilderBase<CustomerCreated> {
              }
            }
            """;

    private final AvroToStringRewriter rewriter = new AvroToStringRewriter();

    @Test
    void a_generated_record_gets_a_redacted_toString() {
        AvroToStringRewriter.Rewrite rewrite = rewriter.rewrite(GENERATED);

        assertThat(rewrite.count()).isEqualTo(1);
        assertThat(rewrite.source())
                .contains("public String toString() {")
                .contains("return io.xlogpolicy.avro.AvroLogRedactor.toSafeString(this);")
                .contains("private java.lang.CharSequence id;");
    }

    @Test
    void the_method_keeps_its_javadoc_and_the_generated_indentation() {
        String source = rewriter.rewrite(GENERATED).source();

        assertThat(source).endsWith("""
                  }

                  /**
                   * Rendered with every field's x-log-policy applied; added by x-log-policy-maven-plugin.
                   * Use {@code SpecificData.get().toString(this)} when the unredacted form is genuinely needed.
                   */
                  @Override
                  public String toString() {
                    return io.xlogpolicy.avro.AvroLogRedactor.toSafeString(this);
                  }
                }
                """);
    }

    @Test
    void the_builder_is_left_alone() {
        String source = rewriter.rewrite(GENERATED).source();

        assertThat(source.indexOf("toSafeString")).isEqualTo(source.lastIndexOf("toSafeString"));
    }

    @Test
    void rewriting_twice_changes_nothing() {
        String once = rewriter.rewrite(GENERATED).source();
        AvroToStringRewriter.Rewrite twice = rewriter.rewrite(once);

        assertThat(twice.count()).isZero();
        assertThat(twice.source()).isEqualTo(once);
        assertThat(twice.skipped()).isEmpty();
    }

    @Test
    void a_hand_written_toString_is_kept_and_reported() {
        String custom = GENERATED.replace("  private java.lang.CharSequence id;",
                "  private java.lang.CharSequence id;\n  @Override public String toString() { return \"x\"; }");

        AvroToStringRewriter.Rewrite rewrite = rewriter.rewrite(custom);

        assertThat(rewrite.count()).isZero();
        assertThat(rewrite.skipped()).containsExactly("CustomerCreated");
    }

    @Test
    void a_class_that_is_not_an_avro_record_is_untouched() {
        String plain = "package x; public class Plain { }";

        assertThat(rewriter.rewrite(plain).count()).isZero();
    }
}
