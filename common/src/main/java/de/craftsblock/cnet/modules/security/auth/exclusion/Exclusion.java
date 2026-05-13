package de.craftsblock.cnet.modules.security.auth.exclusion;

import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.utils.Scheme;
import org.intellij.lang.annotations.RegExp;

import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Pattern;

/**
 * Represents a generic authentication exclusion rule used by the
 * authentication chain to bypass authentication for specific routes
 * or websocket paths.
 * <p>
 * Exclusions are evaluated before the authentication chain is executed.
 * If a request or connection matches an exclusion rule, the authentication
 * process is skipped entirely for the corresponding exchange.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see Scheme
 * @since 1.0.0
 */
public sealed interface Exclusion permits Exclusion.HttpExclusion, Exclusion.WebSocketExclusion {

    /**
     * Returns the network scheme this exclusion applies to.
     *
     * @return The associated {@link Scheme}.
     */
    Scheme scheme();

    /**
     * Returns the path pattern used to match incoming requests
     * or websocket connections against this exclusion rule.
     *
     * @return A compiled {@link Pattern} used for matching paths.
     */
    Pattern path();

    /**
     * Sanitizes the path for usage in the exclusion. This also
     * converts the path to a pattern.
     *
     * @param path The path to sanitize.
     * @return The sanitized path pattern.
     */
    static Pattern sanitizePattern(@RegExp String path) {
        String sanitized = path.trim()
                .replaceAll("//+", "/")
                .replaceAll("/$", "/?");
        if (!sanitized.startsWith("/")) {
            return Pattern.compile("/" + sanitized);
        }

        return Pattern.compile(sanitized);
    }

    /**
     * Represents an HTTP-specific exclusion rule that additionally
     * restricts the exclusion to specific HTTP methods.
     * <p>
     * If the request path matches the configured pattern and the
     * HTTP method is contained in the defined method set, the
     * authentication process will be skipped.
     *
     * @param scheme  The scheme this exclusion applies to (always {@link Scheme#HTTP}).
     * @param path    The compiled regex pattern used to match request paths.
     * @param methods The set of HTTP methods that are excluded from authentication.
     */
    record HttpExclusion(Scheme scheme, Pattern path, HashSet<HttpMethod> methods) implements Exclusion {

        /**
         * Creates a new {@link HttpExclusion} rule for the given path and methods.
         *
         * @param path    The regex pattern used to match request paths.
         * @param methods The HTTP methods to exclude from authentication.
         */
        public HttpExclusion(@RegExp String path, HttpMethod... methods) {
            this(Scheme.HTTP, sanitizePattern(path), new HashSet<>(Arrays.asList(HttpMethod.normalize(methods))));
        }

    }

    /**
     * Represents a websocket-specific exclusion rule.
     * <p>
     * If the websocket path matches the configured pattern,
     * authentication will be skipped for the connection attempt.
     *
     * @param scheme The scheme this exclusion applies to (always {@link Scheme#WS}).
     * @param path   The compiled regex pattern used to match websocket paths.
     */
    record WebSocketExclusion(Scheme scheme, Pattern path) implements Exclusion {

        /**
         * Creates a new {@link WebSocketExclusion} rule for the given path.
         *
         * @param path The regex pattern used to match websocket paths.
         */
        public WebSocketExclusion(@RegExp String path) {
            this(Scheme.WS, sanitizePattern(path));
        }

    }


}