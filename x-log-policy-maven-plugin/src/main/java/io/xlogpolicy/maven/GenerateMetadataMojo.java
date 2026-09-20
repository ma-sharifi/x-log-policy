package io.xlogpolicy.maven;

import io.xlogpolicy.core.metadata.LogPolicyMetadata;
import io.xlogpolicy.core.metadata.PolicyMetadataIO;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * Writes the policy registry the starter reads at runtime.
 *
 * <p>The registry is what makes the contract apply to code the generator never touched: hand-written
 * DTOs, types from another library, and free-form {@code Map} payloads all resolve through it.
 */
@Mojo(name = "generate-metadata",
        defaultPhase = LifecyclePhase.GENERATE_RESOURCES,
        threadSafe = true,
        requiresProject = true)
public class GenerateMetadataMojo extends AbstractSpecMojo {

    /** Directory the registry is written into; defaults to the module's classes output. */
    @Parameter(defaultValue = "${project.build.outputDirectory}", property = "x-log-policy.outputDirectory")
    private File outputDirectory;

    /** Location of the registry inside the artifact. Changing it also requires changing the starter. */
    @Parameter(defaultValue = LogPolicyMetadata.RESOURCE_PATH, property = "x-log-policy.resourcePath")
    private String resourcePath;

    /** Fails the build when no field in any document declares a policy — usually a wiring mistake. */
    @Parameter(defaultValue = "false", property = "x-log-policy.failOnEmpty")
    private boolean failOnEmpty;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("x-log-policy: generate-metadata skipped");
            return;
        }
        Scan scan = scanSpecs();
        LogPolicyMetadata metadata = scan.metadata();

        if (metadata.isEmpty()) {
            String message = "x-log-policy: no " + SpecPolicyScanner.EXTENSION
                    + " declarations found; nothing to redact at runtime";
            if (failOnEmpty) {
                throw new MojoExecutionException(message);
            }
            getLog().warn(message);
        }

        File target = new File(outputDirectory, resourcePath);
        try {
            Files.createDirectories(target.getParentFile().toPath());
            try (OutputStream out = Files.newOutputStream(target.toPath())) {
                PolicyMetadataIO.write(metadata, out);
            }
        } catch (IOException ex) {
            throw new MojoExecutionException("Could not write " + target, ex);
        }

        getLog().info("x-log-policy: wrote " + metadata.schemas().size() + " schema(s), "
                + metadata.byFieldName().size() + " distinct field name(s) to " + target);
    }
}
