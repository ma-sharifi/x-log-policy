package io.xlogpolicy.core;

import java.nio.charset.StandardCharsets;

/**
 * Tuning for the redactor. Every limit exists so that logging can never become the thing that breaks
 * or floods the application.
 *
 * @param maskToken         replacement used by {@link PolicyType#MASK}
 * @param partialKeep       default number of trailing characters kept by {@link PolicyType#PARTIAL}
 * @param digestLength      hex characters kept from {@code HASH} / {@code HMAC} digests
 * @param hmacSecret        key for {@code HMAC} / {@code TOKENIZE}; a random per-JVM key when absent
 * @param maxStringLength   safe string values longer than this are truncated, {@code 0} disables
 * @param maxJsonLength     the rendered JSON is truncated past this length, {@code 0} disables
 * @param maxDepth          maximum nesting depth; deeper graphs (and cycles) abort the rendering
 * @param maxCollectionSize elements rendered per redacted collection, {@code 0} disables
 * @param prettyPrint       whether safe JSON is indented
 */
public record RedactionSettings(
        String maskToken,
        int partialKeep,
        int digestLength,
        byte[] hmacSecret,
        int maxStringLength,
        int maxJsonLength,
        int maxDepth,
        int maxCollectionSize,
        boolean prettyPrint) {

    public static final String DEFAULT_MASK_TOKEN = "***";

    public RedactionSettings {
        if (maskToken == null || maskToken.isEmpty()) {
            maskToken = DEFAULT_MASK_TOKEN;
        }
        if (partialKeep < 0) {
            throw new IllegalArgumentException("partialKeep must not be negative");
        }
        if (digestLength < 4) {
            throw new IllegalArgumentException("digestLength must be at least 4");
        }
        if (maxDepth < 1) {
            throw new IllegalArgumentException("maxDepth must be at least 1");
        }
        if (hmacSecret == null || hmacSecret.length == 0) {
            hmacSecret = randomKey();
        }
    }

    public static RedactionSettings defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return key;
    }

    public static final class Builder {
        private String maskToken = DEFAULT_MASK_TOKEN;
        private int partialKeep = 4;
        private int digestLength = 8;
        private byte[] hmacSecret;
        private int maxStringLength = 2_048;
        private int maxJsonLength = 16_384;
        private int maxDepth = 24;
        private int maxCollectionSize = 100;
        private boolean prettyPrint;

        public Builder maskToken(String maskToken) {
            this.maskToken = maskToken;
            return this;
        }

        public Builder partialKeep(int partialKeep) {
            this.partialKeep = partialKeep;
            return this;
        }

        public Builder digestLength(int digestLength) {
            this.digestLength = digestLength;
            return this;
        }

        public Builder hmacSecret(byte[] hmacSecret) {
            this.hmacSecret = hmacSecret;
            return this;
        }

        public Builder hmacSecret(String hmacSecret) {
            this.hmacSecret = hmacSecret == null || hmacSecret.isBlank()
                    ? null : hmacSecret.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public Builder maxStringLength(int maxStringLength) {
            this.maxStringLength = maxStringLength;
            return this;
        }

        public Builder maxJsonLength(int maxJsonLength) {
            this.maxJsonLength = maxJsonLength;
            return this;
        }

        public Builder maxDepth(int maxDepth) {
            this.maxDepth = maxDepth;
            return this;
        }

        public Builder maxCollectionSize(int maxCollectionSize) {
            this.maxCollectionSize = maxCollectionSize;
            return this;
        }

        public Builder prettyPrint(boolean prettyPrint) {
            this.prettyPrint = prettyPrint;
            return this;
        }

        public RedactionSettings build() {
            return new RedactionSettings(maskToken, partialKeep, digestLength, hmacSecret,
                    maxStringLength, maxJsonLength, maxDepth, maxCollectionSize, prettyPrint);
        }
    }
}
