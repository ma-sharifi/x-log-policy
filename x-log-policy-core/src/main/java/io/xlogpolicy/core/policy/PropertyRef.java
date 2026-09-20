package io.xlogpolicy.core.policy;

import io.xlogpolicy.core.LogPolicy;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Locale;
import java.util.Objects;

/**
 * Identifies the property being serialized, together with any {@link LogPolicy} annotations already
 * found on it.
 *
 * <p>The Jackson layer builds these from {@code BeanPropertyWriter}, where the annotated member is
 * known exactly (so renamed properties, records and getter-only properties all work). Callers outside
 * Jackson use {@link #of(Class, String)}, which falls back to reflection.
 *
 * @param owner          declaring type
 * @param name           property name as it appears in JSON
 * @param implicitName   underlying field or accessor name, equal to {@code name} when not renamed
 * @param onProperty     annotation found on the field / accessor, may be {@code null}
 * @param onType         annotation found on the declaring type, may be {@code null}
 */
public record PropertyRef(Class<?> owner, String name, String implicitName, LogPolicy onProperty, LogPolicy onType) {

    public PropertyRef {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(name, "name");
        implicitName = implicitName == null || implicitName.isBlank() ? name : implicitName;
    }

    /** Builds a reference by looking the property up reflectively on {@code owner}. */
    public static PropertyRef of(Class<?> owner, String propertyName) {
        LogPolicy onProperty = findOnField(owner, propertyName);
        if (onProperty == null) {
            onProperty = findOnAccessor(owner, propertyName);
        }
        return new PropertyRef(owner, propertyName, propertyName, onProperty, owner.getAnnotation(LogPolicy.class));
    }

    /** A reference for a value that has no declaring type, such as a map entry or a raw JSON field. */
    public static PropertyRef ofFieldName(String propertyName) {
        return new PropertyRef(Void.class, propertyName, propertyName, null, null);
    }

    public boolean hasOwner() {
        return owner != Void.class;
    }

    private static LogPolicy findOnField(Class<?> owner, String propertyName) {
        for (Class<?> type = owner; type != null && type != Object.class; type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                if (field.getName().equals(propertyName)) {
                    return field.getAnnotation(LogPolicy.class);
                }
            }
        }
        return null;
    }

    private static LogPolicy findOnAccessor(Class<?> owner, String propertyName) {
        String capitalized = propertyName.isEmpty() ? propertyName
                : Character.toUpperCase(propertyName.charAt(0)) + propertyName.substring(1);
        String[] candidates = {propertyName, "get" + capitalized, "is" + capitalized};
        for (Class<?> type = owner; type != null && type != Object.class; type = type.getSuperclass()) {
            for (Method method : type.getDeclaredMethods()) {
                if (method.getParameterCount() != 0) {
                    continue;
                }
                for (String candidate : candidates) {
                    if (method.getName().equals(candidate)) {
                        LogPolicy annotation = method.getAnnotation(LogPolicy.class);
                        if (annotation != null) {
                            return annotation;
                        }
                    }
                }
            }
        }
        return null;
    }

    /** Key used for caching and for {@code Schema.property} style configuration lookups. */
    public String qualifiedName() {
        return (hasOwner() ? owner.getSimpleName() : "*") + "." + name;
    }

    String lowerCaseName() {
        return name.toLowerCase(Locale.ROOT);
    }
}
