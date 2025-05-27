package de.craftsblock.cnet.modules.security.auth.token;

import de.craftsblock.cnet.modules.security.utils.Entity;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.api.http.HttpMethod;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * This class represents a permission model for a token, defining access
 * control based on a combination of path patterns, domain patterns, and http methods.
 *
 * @param path    a regular expression pattern representing the allowed path.
 * @param domain  a regular expression pattern representing the allowed domain.
 * @param methods a variable number of {@link HttpMethod} values representing
 *                the allowed http methods (e.g., GET, POST).
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.1.1
 * @since 1.0.0-SNAPSHOT
 */
public record TokenPermission(long id, String path, String domain, HttpMethod... methods) implements Entity {

    /**
     * Checks if a given pattern is a wildcard pattern.
     * A pattern is considered a wildcard if it is "*" or ".*".
     *
     * @param pattern the pattern to check.
     * @return {@code true} if the pattern is a wildcard, {@code false} otherwise.
     */
    private boolean isWildcard(String pattern) {
        return pattern.equals("*") || pattern.equals(".*");
    }

    /**
     * Checks if a given value is allowed by matching it against the provided pattern.
     *
     * @param value   the value to be checked (e.g., a path or domain).
     * @param pattern the pattern to match against.
     * @return {@code true} if the value matches the pattern, {@code false} otherwise.
     */
    private boolean isAllowed(String value, String pattern) {
        return value.matches(pattern);
    }

    /**
     * Checks if the path pattern is a wildcard.
     *
     * @return {@code true} if the path pattern is a wildcard, {@code false} otherwise.
     */
    boolean isPathWildcard() {
        return isWildcard(path());
    }

    /**
     * Determines if a given path is allowed based on the defined path pattern.
     * A path is allowed if it either matches the pattern or if the pattern is a wildcard.
     *
     * @param path the path to check.
     * @return {@code true} if the path is allowed, {@code false} otherwise.
     */
    boolean isPathAllowed(String path) {
        return isPathWildcard() || isAllowed(path, path());
    }

    /**
     * Checks if the domain pattern is a wildcard.
     *
     * @return {@code true} if the domain pattern is a wildcard, {@code false} otherwise.
     */
    boolean isDomainWildcard() {
        return isWildcard(domain());
    }

    /**
     * Determines if a given domain is allowed based on the defined domain pattern.
     * A domain is allowed if it either matches the pattern or if the pattern is a wildcard.
     *
     * @param domain the domain to check.
     * @return {@code true} if the domain is allowed, {@code false} otherwise.
     */
    boolean isDomainAllowed(String domain) {
        return isDomainWildcard() || isAllowed(domain, domain());
    }

    /**
     * Determines if a given http method is allowed based on the defined allowed methods.
     *
     * @param method the http method to check.
     * @return {@code true} if the http method is allowed, {@code false} otherwise.
     */
    public boolean isHttpMethodAllowed(HttpMethod method) {
        List<HttpMethod> methods = Arrays.asList(methods());
        return methods.contains(HttpMethod.ALL) || methods.contains(HttpMethod.ALL_RAW) || methods.contains(method);
    }

    /**
     * Serializes the {@link TokenPermission} object into a {@link Json} object.
     * The serialization includes the path, domain, and allowed http methods.
     *
     * @return a {@link Json} object representing the serialized permission details.
     */
    @Override
    public Json serialize() {
        return Json.empty()
                .set("id", id())
                .set("path", path())
                .set("domain", domain())
                .set("methods", Arrays.stream(methods()).map(HttpMethod::name).toList());
    }

    /**
     * Creates a new {@link TokenPermission} with a given path and http methods.
     * The domain pattern defaults to a wildcard (".*").
     *
     * @param path    the regular expression pattern for the path.
     * @param methods the allowed http methods for this permission.
     * @return a new {@link TokenPermission} instance.
     */
    public static TokenPermission of(String path, HttpMethod... methods) {
        return TokenPermission.of(path, ".*", methods);
    }

    /**
     * Creates a new {@link TokenPermission} with a given path, domain, and http methods.
     *
     * @param path    the regular expression pattern for the path.
     * @param domain  the regular expression pattern for the domain.
     * @param methods the allowed http methods for this permission.
     * @return a new {@link TokenPermission} instance.
     */
    public static TokenPermission of(String path, String domain, HttpMethod... methods) {
        return TokenPermission.of(Snowflake.generate(), path, domain, methods);
    }

    /**
     * Creates a new {@link TokenPermission} with the specified id, path, domain, and http methods.
     *
     * @param id      the unique id of the permission (usually generated via Snowflake or read from storage).
     * @param path    the regular expression pattern for the path.
     * @param domain  the regular expression pattern for the domain.
     * @param methods the allowed http methods for this permission.
     * @return a new {@link TokenPermission} instance.
     */
    public static TokenPermission of(long id, String path, String domain, HttpMethod... methods) {
        return new TokenPermission(id, path, domain, methods);
    }

}
