package io.xlogpolicy.core.redaction;

import io.xlogpolicy.core.FieldPolicy;
import io.xlogpolicy.core.PolicyType;
import io.xlogpolicy.core.RedactionSettings;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * The redactions shipped with x-log-policy. One instance per {@link RedactionSettings}.
 */
public final class BuiltinRedactions {

    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final int MAX_MASK_RUN = 32;

    private BuiltinRedactions() {
    }

    /** @return mask, partial, hash, hmac and tokenize redactions bound to {@code settings} */
    public static List<ValueRedaction> create(RedactionSettings settings, Tokenizer tokenizer) {
        HmacRedaction hmac = new HmacRedaction(settings);
        Tokenizer effectiveTokenizer = tokenizer != null ? tokenizer : value -> "tok_" + hmac.digest(value);
        return List.of(
                new MaskRedaction(settings),
                new PartialRedaction(settings),
                new HashRedaction(settings),
                hmac,
                new TokenizeRedaction(effectiveTokenizer));
    }

    /** Replaces the whole value with a fixed token. */
    public static final class MaskRedaction implements ValueRedaction {
        private final String maskToken;

        public MaskRedaction(RedactionSettings settings) {
            this.maskToken = settings.maskToken();
        }

        @Override
        public String name() {
            return PolicyType.MASK.name();
        }

        @Override
        public String redact(Object value, FieldPolicy policy) {
            return maskToken;
        }
    }

    /** Keeps the trailing characters, masking everything before them. */
    public static final class PartialRedaction implements ValueRedaction {
        private final RedactionSettings settings;

        public PartialRedaction(RedactionSettings settings) {
            this.settings = settings;
        }

        @Override
        public String name() {
            return PolicyType.PARTIAL.name();
        }

        @Override
        public String redact(Object value, FieldPolicy policy) {
            String text = String.valueOf(value);
            int keep = policy.keepOrDefault(settings.partialKeep());
            if (keep <= 0 || text.length() <= keep) {
                return settings.maskToken();
            }
            int masked = Math.min(text.length() - keep, MAX_MASK_RUN);
            return "*".repeat(masked) + text.substring(text.length() - keep);
        }
    }

    /** Unkeyed SHA-256. Correlatable, but so is a dictionary attack on a low-entropy value. */
    public static final class HashRedaction implements ValueRedaction {
        private final RedactionSettings settings;

        public HashRedaction(RedactionSettings settings) {
            this.settings = settings;
        }

        @Override
        public String name() {
            return PolicyType.HASH.name();
        }

        @Override
        public String redact(Object value, FieldPolicy policy) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(String.valueOf(value).getBytes(StandardCharsets.UTF_8));
                return "sha256:" + hex(hash, settings.digestLength());
            } catch (NoSuchAlgorithmException ex) {
                return settings.maskToken();
            }
        }
    }

    /** Keyed HMAC-SHA256: the same input yields the same token, without revealing the input. */
    public static final class HmacRedaction implements ValueRedaction {
        private final RedactionSettings settings;
        private final SecretKeySpec key;
        private final ThreadLocal<Mac> macs;

        public HmacRedaction(RedactionSettings settings) {
            this.settings = settings;
            this.key = new SecretKeySpec(settings.hmacSecret(), "HmacSHA256");
            this.macs = ThreadLocal.withInitial(() -> {
                try {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(key);
                    return mac;
                } catch (java.security.GeneralSecurityException ex) {
                    throw new IllegalStateException("HmacSHA256 is unavailable", ex);
                }
            });
        }

        @Override
        public String name() {
            return PolicyType.HMAC.name();
        }

        @Override
        public String redact(Object value, FieldPolicy policy) {
            return "hmac:" + digest(String.valueOf(value));
        }

        String digest(String value) {
            try {
                Mac mac = macs.get();
                mac.reset();
                return hex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)), settings.digestLength());
            } catch (RuntimeException ex) {
                return settings.maskToken();
            }
        }
    }

    /** Delegates to the configured {@link Tokenizer}, typically a real tokenization service. */
    public static final class TokenizeRedaction implements ValueRedaction {
        private final Tokenizer tokenizer;

        public TokenizeRedaction(Tokenizer tokenizer) {
            this.tokenizer = tokenizer;
        }

        @Override
        public String name() {
            return PolicyType.TOKENIZE.name();
        }

        @Override
        public String redact(Object value, FieldPolicy policy) {
            String token = tokenizer.tokenize(String.valueOf(value));
            return token == null ? RedactionSettings.DEFAULT_MASK_TOKEN : token;
        }
    }

    private static String hex(byte[] bytes, int hexChars) {
        int length = Math.min(hexChars, bytes.length * 2);
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < bytes.length && out.length() < length; i++) {
            out.append(HEX[(bytes[i] >> 4) & 0xF]);
            if (out.length() < length) {
                out.append(HEX[bytes[i] & 0xF]);
            }
        }
        return out.toString();
    }
}
