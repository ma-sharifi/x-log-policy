package io.xlogpolicy.spring.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.xlogpolicy.core.LogRedactor;
import io.xlogpolicy.spring.XLogPolicyProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Logs each request and response with every payload run through the policies.
 *
 * <p>A JSON or form body is redacted by resolving <em>every key by name</em> against the registry. That
 * is the strongest guarantee available without knowing the handler's DTO type: declared fields get their
 * declared policy and everything else falls to the default policy, so an undocumented field in a request
 * body cannot slip into the log. Because the lookup is by name, body logging needs the build-time
 * registry ({@code META-INF/x-log-policy.json}); annotations alone cannot describe a bare JSON key.
 * Any other media type is summarised as its type and size rather than printed.
 *
 * <p>Headers are opt-in, and the sensitive ones are never logged regardless.
 */
public class LogPolicyLoggingFilter extends OncePerRequestFilter {

    private static final String FORM_TYPE = "application/x-www-form-urlencoded";

    private final LogRedactor redactor;
    private final XLogPolicyProperties.Http config;
    private final Logger log;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ObjectMapper reader = new ObjectMapper();
    private final Set<String> alwaysRedactHeaders;
    private final List<String> includeHeaders;

    public LogPolicyLoggingFilter(LogRedactor redactor, XLogPolicyProperties.Http config) {
        this.redactor = redactor;
        this.config = config;
        this.log = LoggerFactory.getLogger(config.getLoggerName());
        this.alwaysRedactHeaders = lowerCased(config.getAlwaysRedactHeaders());
        // Kept in the spelling the operator configured, because that is also the spelling the OpenAPI
        // document uses, and the registry is keyed by it. Header retrieval itself is case-insensitive.
        this.includeHeaders = List.copyOf(config.getIncludeHeaders());
    }

    private static Set<String> lowerCased(Iterable<String> values) {
        Set<String> result = new LinkedHashSet<>();
        values.forEach(value -> result.add(value.toLowerCase(Locale.ROOT)));
        return result;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!log.isInfoEnabled()) {
            return true;
        }
        String path = request.getRequestURI();
        return config.getExcludePaths().stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        ContentCachingRequestWrapper wrappedRequest = config.isIncludeRequestBody()
                ? new ContentCachingRequestWrapper(request, config.getMaxPayloadLength())
                : null;
        ContentCachingResponseWrapper wrappedResponse = config.isIncludeResponseBody()
                ? new ContentCachingResponseWrapper(response)
                : null;

        HttpServletRequest effectiveRequest = wrappedRequest != null ? wrappedRequest : request;
        HttpServletResponse effectiveResponse = wrappedResponse != null ? wrappedResponse : response;
        long startedAt = System.nanoTime();
        try {
            chain.doFilter(effectiveRequest, effectiveResponse);
        } finally {
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
            try {
                logExchange(request, response, wrappedRequest, wrappedResponse, millis);
            } catch (RuntimeException failure) {
                // Logging must never turn into a failed request.
                log.debug("x-log-policy: could not log this exchange: {}", failure.getClass().getName());
            }
            if (wrappedResponse != null) {
                wrappedResponse.copyBodyToResponse();
            }
        }
    }

    private void logExchange(HttpServletRequest request, HttpServletResponse response,
                             ContentCachingRequestWrapper wrappedRequest,
                             ContentCachingResponseWrapper wrappedResponse, long millis) {
        StringBuilder line = new StringBuilder(160);
        line.append(request.getMethod()).append(' ').append(request.getRequestURI());
        String query = request.getQueryString();
        if (query != null) {
            line.append('?').append(redactor.redactText(query));
        }
        line.append(" -> ").append(response.getStatus()).append(" (").append(millis).append("ms)");

        String headers = headers(request);
        if (!headers.isEmpty()) {
            line.append(" headers=").append(headers);
        }
        if (wrappedRequest != null) {
            String body = body(wrappedRequest.getContentAsByteArray(), wrappedRequest.getCharacterEncoding(),
                    request.getContentType());
            if (!body.isEmpty()) {
                line.append(" request=").append(body);
            }
        }
        if (wrappedResponse != null) {
            String body = body(wrappedResponse.getContentAsByteArray(), wrappedResponse.getCharacterEncoding(),
                    response.getContentType());
            if (!body.isEmpty()) {
                line.append(" response=").append(body);
            }
        }
        log.info("{}", line);
    }

    private String headers(HttpServletRequest request) {
        if (includeHeaders.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (String name : includeHeaders) {
            String value = request.getHeader(name);
            if (value == null) {
                continue;
            }
            out.append(out.isEmpty() ? "{" : ", ").append(name).append('=');
            if (alwaysRedactHeaders.contains(name.toLowerCase(Locale.ROOT))) {
                out.append("***");
            } else {
                out.append(redactor.redactValue(name, value));
            }
        }
        return out.isEmpty() ? "" : out.append('}').toString();
    }

    /**
     * A JSON or form body is redacted key by key against the registry, so an undeclared field falls to
     * the default policy. Any other media type is summarised rather than printed: the text redactor
     * cannot see structure in free-form content, and guessing would mean leaking.
     */
    private String body(byte[] content, String encoding, String contentType) {
        if (content == null || content.length == 0 || contentType == null) {
            return "";
        }
        String type = baseType(contentType);
        Charset charset = charset(encoding);
        String text = new String(content, 0, Math.min(content.length, config.getMaxPayloadLength()), charset);

        if (type.endsWith("json")) {
            try {
                return redactor.toSafeJson(reader.readValue(text, Object.class));
            } catch (IOException | RuntimeException notJson) {
                // Truncated or malformed: still never logged raw.
                return "<" + type + ", " + content.length + " bytes, unparseable>";
            }
        }
        if (FORM_TYPE.equals(type)) {
            return redactor.toSafeJson(formFields(text, charset));
        }
        return "<" + type + ", " + content.length + " bytes>";
    }

    /** Form fields resolve by name exactly as JSON keys do. */
    private Map<String, Object> formFields(String text, Charset charset) {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (String pair : text.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int separator = pair.indexOf('=');
            String name = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            fields.put(URLDecoder.decode(name, charset), URLDecoder.decode(value, charset));
        }
        return fields;
    }

    private static Charset charset(String encoding) {
        try {
            return encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
        } catch (RuntimeException unsupported) {
            return StandardCharsets.UTF_8;
        }
    }

    private static String baseType(String contentType) {
        int separator = contentType.indexOf(';');
        return (separator < 0 ? contentType : contentType.substring(0, separator)).trim().toLowerCase(Locale.ROOT);
    }
}
