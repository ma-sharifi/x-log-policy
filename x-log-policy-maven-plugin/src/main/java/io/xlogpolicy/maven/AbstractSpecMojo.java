package io.xlogpolicy.maven;

import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/** Shared spec handling: locating the documents, scanning them and reporting parse problems. */
abstract class AbstractSpecMojo extends AbstractMojo {

    /**
     * OpenAPI documents to read. Paths are resolved against the project base directory; URLs are
     * accepted as well.
     */
    @Parameter(property = "x-log-policy.specs", required = true)
    protected List<String> specs;

    /** Skips this goal entirely. */
    @Parameter(property = "x-log-policy.skip", defaultValue = "false")
    protected boolean skip;

    /**
     * Fails the build when a document cannot be parsed, or when a {@code x-log-policy} declaration is
     * malformed. Leaving this on is what keeps a typo from silently disabling redaction.
     */
    @Parameter(property = "x-log-policy.failOnSpecError", defaultValue = "true")
    protected boolean failOnSpecError;

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    /** Scans every configured spec and merges the results. */
    protected Scan scanSpecs() throws MojoExecutionException {
        if (specs == null || specs.isEmpty()) {
            throw new MojoExecutionException("No <specs> configured for x-log-policy-maven-plugin");
        }
        LogPolicyMetadata metadata = LogPolicyMetadata.empty();
        List<SpecPolicyScanner.PropertyFinding> findings = new ArrayList<>();
        List<String> problems = new ArrayList<>();

        for (String spec : specs) {
            String location = resolve(spec);
            getLog().info("x-log-policy: reading " + location);
            SpecPolicyScanner.ScanResult result = SpecPolicyScanner.scan(location);
            metadata = metadata.merge(result.metadata());
            findings.addAll(result.findings());
            result.problems().forEach(problem -> problems.add(spec + ": " + problem));
        }

        if (!problems.isEmpty()) {
            String message = "x-log-policy found problems in the OpenAPI document(s):"
                    + System.lineSeparator() + "  - " + String.join(System.lineSeparator() + "  - ", problems);
            if (failOnSpecError) {
                throw new MojoExecutionException(message);
            }
            getLog().warn(message);
        }
        return new Scan(metadata, findings);
    }

    private String resolve(String spec) {
        if (spec.contains("://")) {
            return spec;
        }
        File file = new File(spec);
        if (!file.isAbsolute()) {
            file = new File(project.getBasedir(), spec);
        }
        return file.getAbsolutePath();
    }

    record Scan(LogPolicyMetadata metadata, List<SpecPolicyScanner.PropertyFinding> findings) {
    }
}
