package io.xlogpolicy.maven;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Makes the {@code toString()} of every Avro-generated record redacted, per the {@code x-log-policy}
 * declarations in its schema.
 *
 * <p>Runs after {@code avro-maven-plugin} and before compilation. Needs no {@code <specs>}: the policy is
 * read at runtime from the schema embedded in each class. The module must depend on
 * {@code x-log-policy-avro}.
 */
@Mojo(name = "avro-safe-tostring",
        defaultPhase = LifecyclePhase.PROCESS_SOURCES,
        threadSafe = true,
        requiresProject = true)
public class AvroToStringMojo extends AbstractMojo {

    /** Source roots to rewrite. Defaults to the directory avro-maven-plugin writes to. */
    @Parameter(property = "x-log-policy.avroSourceDirectories")
    private List<File> sourceDirectories;

    /** Reports what would change without touching any file. */
    @Parameter(property = "x-log-policy.dryRun", defaultValue = "false")
    private boolean dryRun;

    /** Skips this goal entirely. */
    @Parameter(property = "x-log-policy.skip", defaultValue = "false")
    private boolean skip;

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("x-log-policy: avro-safe-tostring skipped");
            return;
        }
        AvroToStringRewriter rewriter = new AvroToStringRewriter();
        int scanned = 0;
        int modified = 0;
        List<String> problems = new ArrayList<>();
        for (File root : effectiveSourceDirectories()) {
            try {
                AvroToStringRewriter.Result result = rewriter.rewriteTree(root.toPath(), dryRun);
                scanned += result.filesScanned();
                modified += result.filesModified();
                problems.addAll(result.problems());
            } catch (IOException ex) {
                throw new MojoExecutionException("Could not rewrite sources under " + root, ex);
            }
        }
        getLog().info("x-log-policy: redacted toString() in " + modified + " of " + scanned + " file(s)"
                + (dryRun ? " (dry run, nothing written)" : ""));
        problems.forEach(problem -> getLog().warn("x-log-policy: " + problem));
    }

    private List<File> effectiveSourceDirectories() {
        if (sourceDirectories != null && !sourceDirectories.isEmpty()) {
            return sourceDirectories;
        }
        return List.of(new File(project.getBuild().getDirectory(), "generated-sources/avro"));
    }
}
