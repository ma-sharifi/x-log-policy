package io.xlogpolicy.maven;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Stamps {@code @LogPolicy} onto generated model sources, straight from the spec.
 *
 * <p>Runs after the model generator and before compilation, so the annotations end up in the compiled
 * classes. Re-running is safe: a field that already declares a policy is left alone.
 */
@Mojo(name = "annotate-sources",
        defaultPhase = LifecyclePhase.PROCESS_SOURCES,
        threadSafe = true,
        requiresProject = true)
public class AnnotateSourcesMojo extends AbstractSpecMojo {

    /**
     * Source roots to rewrite. Defaults to the directory openapi-generator writes to; point it at
     * {@code src/main/java} to annotate hand-written models instead (they are rewritten in place).
     */
    @Parameter(property = "x-log-policy.sourceDirectories")
    private List<File> sourceDirectories;

    /** Reports what would change without touching any file. */
    @Parameter(property = "x-log-policy.dryRun", defaultValue = "false")
    private boolean dryRun;

    /** Fails the build when no annotation could be placed, which usually means the names do not match. */
    @Parameter(property = "x-log-policy.failOnNothingAnnotated", defaultValue = "false")
    private boolean failOnNothingAnnotated;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("x-log-policy: annotate-sources skipped");
            return;
        }
        Scan scan = scanSpecs();
        SourceAnnotator annotator = new SourceAnnotator(scan.metadata());

        int annotations = 0;
        int modified = 0;
        int scanned = 0;
        List<String> problems = new ArrayList<>();

        for (File root : effectiveSourceDirectories()) {
            if (!root.isDirectory()) {
                getLog().debug("x-log-policy: no sources under " + root);
                continue;
            }
            try {
                SourceAnnotator.Result result = annotator.annotateTree(root.toPath(), dryRun);
                scanned += result.filesScanned();
                modified += result.filesModified();
                annotations += result.annotations();
                problems.addAll(result.problems());
            } catch (IOException ex) {
                throw new MojoExecutionException("Could not annotate sources under " + root, ex);
            }
        }

        getLog().info("x-log-policy: " + annotations + " annotation(s) in " + modified + " of " + scanned
                + " file(s)" + (dryRun ? " (dry run, nothing written)" : ""));
        problems.forEach(problem -> getLog().warn("x-log-policy: " + problem));

        if (annotations == 0 && failOnNothingAnnotated) {
            throw new MojoExecutionException("x-log-policy: no @LogPolicy annotation could be placed."
                    + " Check that the model class names match the schema names, and that <sourceDirectories>"
                    + " points at the generated sources.");
        }
    }

    private List<File> effectiveSourceDirectories() {
        if (sourceDirectories != null && !sourceDirectories.isEmpty()) {
            return sourceDirectories;
        }
        File generated = new File(project.getBuild().getDirectory(), "generated-sources/openapi/src/main/java");
        return List.of(generated);
    }
}
