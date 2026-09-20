package io.xlogpolicy.core.jackson;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.time.temporal.TemporalAccessor;
import java.util.Calendar;
import java.util.Currency;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

/**
 * Decides whether a property holds a <em>value</em> (something that ends up in the log as a single
 * token) or a <em>structure</em> that should be descended into.
 *
 * <p>This distinction is what makes fail-closed defaulting usable: an unpoliced {@code String} is
 * masked, while an unpoliced nested object is walked so that its own fields keep their own policies.
 * Anything whose shape cannot be known — {@code Object}, a {@code JsonNode}, a raw {@code Map} — counts
 * as a value, so it is masked rather than leaked.
 */
public final class ValueTypes {

    private ValueTypes() {
    }

    /** @return {@code true} when the default policy should be applied to this type directly */
    public static boolean isValueLike(JavaType type) {
        if (type == null) {
            return true;
        }
        if (type.isArrayType() && type.getRawClass() != byte[].class) {
            return isValueLike(type.getContentType());
        }
        if (type.isCollectionLikeType()) {
            return isValueLike(type.getContentType());
        }
        if (type.isMapLikeType()) {
            // Keys are data, not declarations: handled by MapPolicySerializer, never by the default.
            return false;
        }
        return isValueClass(type.getRawClass());
    }

    /** @return {@code true} when instances of {@code raw} are logged as a single token */
    public static boolean isValueClass(Class<?> raw) {
        if (raw == null) {
            return true;
        }
        return raw.isPrimitive()
                || raw.isEnum()
                || raw == Object.class
                || raw == byte[].class
                || CharSequence.class.isAssignableFrom(raw)
                || Number.class.isAssignableFrom(raw)
                || raw == Boolean.class
                || raw == Character.class
                || raw == BigDecimal.class
                || raw == BigInteger.class
                || raw == UUID.class
                || TemporalAccessor.class.isAssignableFrom(raw)
                || Date.class.isAssignableFrom(raw)
                || Calendar.class.isAssignableFrom(raw)
                || raw == URI.class
                || raw == URL.class
                || raw == Locale.class
                || raw == Currency.class
                || JsonNode.class.isAssignableFrom(raw);
    }

    /** @return {@code true} for text-like types, which are the ones worth truncating */
    public static boolean isTextLike(JavaType type) {
        return type != null && CharSequence.class.isAssignableFrom(type.getRawClass());
    }
}
