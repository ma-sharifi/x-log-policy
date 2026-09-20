package io.xlogpolicy.maven;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Fails the build when a field that looks like personal data carries no {@code x-log-policy}.
 *
 * <p>This is the goal that turns the extension from documentation into a contract: without it, the day
 * someone adds {@code passportNumber} to the spec is the day it starts appearing in the logs.
 */
@Mojo(name = "validate",
        defaultPhase = LifecyclePhase.PROCESS_RESOURCES,
        threadSafe = true,
        requiresProject = true)
public class ValidateMojo extends AbstractSpecMojo {

    /** Whether an uncovered field fails the build, or is only reported. */
    @Parameter(property = "x-log-policy.failOnMissingPolicy", defaultValue = "true")
    private boolean failOnMissingPolicy;

    /**
     * Regular expressions matched against property names. Replaces the built-in list when set; see
     * {@code additionalPatterns} to extend it instead.
     */
    @Parameter(property = "x-log-policy.patterns")
    private List<String> patterns;

    /** Extra patterns, added to the built-in list. */
    @Parameter(property = "x-log-policy.additionalPatterns")
    private List<String> additionalPatterns;

    /**
     * Regular expressions matched against {@code Schema.property} (or the bare property name) that are
     * known not to be personal data, e.g. {@code Country\.name}.
     */
    @Parameter(property = "x-log-policy.excludes")
    private List<String> excludes;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("x-log-policy: validate skipped");
            return;
        }
        Scan scan = scanSpecs();

        List<String> effectivePatterns = new ArrayList<>(
                patterns == null || patterns.isEmpty() ? PiiHeuristics.DEFAULT_PATTERNS : patterns);
        if (additionalPatterns != null) {
            effectivePatterns.addAll(additionalPatterns);
        }
        PiiHeuristics heuristics = new PiiHeuristics(effectivePatterns, excludes);

        List<String> violations = new ArrayList<>();
        int checked = 0;
        for (SpecPolicyScanner.PropertyFinding finding : scan.findings()) {
            checked++;
            // A property pointing at another schema is descended into at runtime, where the nested fields
            // apply their own policies; requiring one here would mask the whole object instead.
            if (!finding.needsPolicy()) {
                continue;
            }
            String qualified = finding.schemaName() + "." + finding.propertyName();
            Optional<String> flagged = heuristics.flag(qualified, finding.propertyName());
            flagged.ifPresent(pattern -> violations.add(qualified + " looks like personal data (matched /"
                    + pattern + "/) but declares no " + SpecPolicyScanner.EXTENSION));
        }

        getLog().info("x-log-policy: checked " + checked + " propert" + (checked == 1 ? "y" : "ies") + ", "
                + scan.findings().stream().filter(SpecPolicyScanner.PropertyFinding::hasPolicy).count()
                + " policied, " + violations.size() + " uncovered");

        if (violations.isEmpty()) {
            return;
        }
        String message = "x-log-policy: " + violations.size() + " field(s) need a policy:"
                + System.lineSeparator() + "  - "
                + String.join(System.lineSeparator() + "  - ", violations)
                + System.lineSeparator()
                + "Add \"" + SpecPolicyScanner.EXTENSION + ": SAFE\" to the ones that are not sensitive,"
                + " or exclude them with <excludes>.";
        if (failOnMissingPolicy) {
            throw new MojoFailureException(message);
        }
        getLog().warn(message);
    }
}
