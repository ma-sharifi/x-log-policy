package io.xlogpolicy.spring;

import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration for {@code x-log-policy}.
 *
 * <pre>{@code
 * x-log-policy:
 *   default-policy: MASK          # fail closed: anything undeclared is hidden
 *   hmac:
 *     secret: ${LOG_HMAC_SECRET}  # required for HMAC / TOKENIZE to correlate across restarts
 *   overrides:
 *     "[Customer.ssn]": DROP
 *   http:
 *     enabled: true
 * }</pre>
 */
@ConfigurationProperties("x-log-policy")
public class XLogPolicyProperties {

    /** Whether x-log-policy is auto-configured at all. */
    private boolean enabled = true;

    /**
     * Policy for values that neither the spec, an annotation nor an override covers. {@code MASK} keeps
     * the application fail-closed: a new personal-data field cannot leak by being forgotten. Set it to
     * {@code SAFE} only if you accept that risk.
     */
    private PolicyType defaultPolicy = PolicyType.MASK;

    /** Whether to read the build-time registry from {@code META-INF/x-log-policy.json}. */
    private boolean loadMetadata = true;

    /** Replacement written for a masked value. */
    private String maskToken = RedactionSettings.DEFAULT_MASK_TOKEN;

    /** Trailing characters kept by {@code PARTIAL} when the field does not say. */
    private int partialKeep = 4;

    /** Hex characters kept from a {@code HASH} or {@code HMAC} digest. */
    private int digestLength = 8;

    /** Safe text longer than this is truncated. Zero disables truncation. */
    private int maxStringLength = 2048;

    /** Rendered JSON longer than this is truncated. Zero disables truncation. */
    private int maxJsonLength = 16384;

    /** Maximum nesting depth; a deeper graph (or a cycle) yields a placeholder instead of output. */
    private int maxDepth = 24;

    /** Elements rendered per redacted collection or free-form map. Zero disables the cap. */
    private int maxCollectionSize = 100;

    /** Whether safe JSON is indented. Useful locally, wasteful in production. */
    private boolean prettyPrint = false;

    /**
     * Highest-precedence policy overrides, keyed by {@code Schema.property}, {@code *.property} or a
     * bare property name. Values are a policy name, optionally parameterised: {@code PARTIAL:4},
     * {@code CUSTOM:myRedaction}. Keys containing a dot need the bracket form: {@code "[Customer.ssn]"}.
     */
    private Map<String, String> overrides = new LinkedHashMap<>();

    private final Hmac hmac = new Hmac();

    private final Http http = new Http();

    /** Keyed digest settings, used by the {@code HMAC} and default {@code TOKENIZE} policies. */
    public static class Hmac {

        /**
         * Secret for keyed digests. Without one a random per-JVM key is generated, which means values
         * stop being correlatable across restarts and instances; a warning is logged when a policy
         * actually needs it. Supply it from the environment, never from a checked-in file.
         */
        private String secret;

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }
    }

    /** Request and response logging. Off by default: it changes what an application writes. */
    public static class Http {

        /** Whether the HTTP payload logging filter is registered. */
        private boolean enabled = false;

        /** Log the request body (redacted). */
        private boolean includeRequestBody = true;

        /** Log the response body (redacted). Doubles the buffering, so off by default. */
        private boolean includeResponseBody = false;

        /** Bytes of each body that are buffered and considered. */
        private int maxPayloadLength = 2048;

        /**
         * Header names to log. Empty means no headers are logged. A listed header is still subject to
         * its policy, and the always-sensitive ones below are never logged whatever this says.
         */
        private List<String> includeHeaders = new ArrayList<>();

        /** Headers that are never logged, whatever {@code includeHeaders} says. */
        private List<String> alwaysRedactHeaders = new ArrayList<>(List.of(
                "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"));

        /** Ant patterns that are not logged at all. */
        private List<String> excludePaths = new ArrayList<>(List.of("/actuator/**"));

        /** Logger the filter writes to, so it can be turned up or down on its own. */
        private String loggerName = "io.xlogpolicy.http";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isIncludeRequestBody() {
            return includeRequestBody;
        }

        public void setIncludeRequestBody(boolean includeRequestBody) {
            this.includeRequestBody = includeRequestBody;
        }

        public boolean isIncludeResponseBody() {
            return includeResponseBody;
        }

        public void setIncludeResponseBody(boolean includeResponseBody) {
            this.includeResponseBody = includeResponseBody;
        }

        public int getMaxPayloadLength() {
            return maxPayloadLength;
        }

        public void setMaxPayloadLength(int maxPayloadLength) {
            this.maxPayloadLength = maxPayloadLength;
        }

        public List<String> getIncludeHeaders() {
            return includeHeaders;
        }

        public void setIncludeHeaders(List<String> includeHeaders) {
            this.includeHeaders = includeHeaders;
        }

        public List<String> getAlwaysRedactHeaders() {
            return alwaysRedactHeaders;
        }

        public void setAlwaysRedactHeaders(List<String> alwaysRedactHeaders) {
            this.alwaysRedactHeaders = alwaysRedactHeaders;
        }

        public List<String> getExcludePaths() {
            return excludePaths;
        }

        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }

        public String getLoggerName() {
            return loggerName;
        }

        public void setLoggerName(String loggerName) {
            this.loggerName = loggerName;
        }
    }

    /** Builds the core settings this configuration describes. */
    public RedactionSettings toRedactionSettings() {
        return RedactionSettings.builder()
                .maskToken(maskToken)
                .partialKeep(partialKeep)
                .digestLength(digestLength)
                .hmacSecret(hmac.getSecret())
                .maxStringLength(maxStringLength)
                .maxJsonLength(maxJsonLength)
                .maxDepth(maxDepth)
                .maxCollectionSize(maxCollectionSize)
                .prettyPrint(prettyPrint)
                .build();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public PolicyType getDefaultPolicy() {
        return defaultPolicy;
    }

    public void setDefaultPolicy(PolicyType defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    public boolean isLoadMetadata() {
        return loadMetadata;
    }

    public void setLoadMetadata(boolean loadMetadata) {
        this.loadMetadata = loadMetadata;
    }

    public String getMaskToken() {
        return maskToken;
    }

    public void setMaskToken(String maskToken) {
        this.maskToken = maskToken;
    }

    public int getPartialKeep() {
        return partialKeep;
    }

    public void setPartialKeep(int partialKeep) {
        this.partialKeep = partialKeep;
    }

    public int getDigestLength() {
        return digestLength;
    }

    public void setDigestLength(int digestLength) {
        this.digestLength = digestLength;
    }

    public int getMaxStringLength() {
        return maxStringLength;
    }

    public void setMaxStringLength(int maxStringLength) {
        this.maxStringLength = maxStringLength;
    }

    public int getMaxJsonLength() {
        return maxJsonLength;
    }

    public void setMaxJsonLength(int maxJsonLength) {
        this.maxJsonLength = maxJsonLength;
    }

    public int getMaxDepth() {
        return maxDepth;
    }

    public void setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth;
    }

    public int getMaxCollectionSize() {
        return maxCollectionSize;
    }

    public void setMaxCollectionSize(int maxCollectionSize) {
        this.maxCollectionSize = maxCollectionSize;
    }

    public boolean isPrettyPrint() {
        return prettyPrint;
    }

    public void setPrettyPrint(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    public Map<String, String> getOverrides() {
        return overrides;
    }

    public void setOverrides(Map<String, String> overrides) {
        this.overrides = overrides;
    }

    public Hmac getHmac() {
        return hmac;
    }

    public Http getHttp() {
        return http;
    }
}
