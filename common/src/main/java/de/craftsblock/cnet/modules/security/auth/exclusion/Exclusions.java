package de.craftsblock.cnet.modules.security.auth.exclusion;

import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.utils.Scheme;
import org.intellij.lang.annotations.RegExp;

import java.util.*;
import java.util.regex.Matcher;

/**
 * Central registry for authentication exclusion rules used by the
 * authentication chain system.
 * <p>
 * This class manages both HTTP and WebSocket exclusions and provides
 * methods to register and evaluate exclusion rules. If a request or
 * connection matches a registered exclusion, authentication will be
 * skipped for that exchange.
 * <p>
 * Exclusions are grouped by {@link Scheme} and evaluated using regex
 * path matching combined with optional HTTP method constraints for
 * HTTP-based rules.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see Exclusion
 * @see Scheme
 * @since 1.0.0
 */
public final class Exclusions {

    private final Map<Scheme, Collection<Exclusion>> exclusions = new EnumMap<>(Scheme.class);

    /**
     * Registers a new HTTP exclusion rule.
     * <p>
     * The exclusion is only added if no identical rule (same path
     * and identical HTTP methods) already exists.
     *
     * @param path    The regex path used to match incoming requests.
     * @param methods The HTTP methods this exclusion applies to.
     * @return This {@link Exclusions} instance for chaining.
     * @throws IllegalArgumentException If no HTTP methods are provided.
     */
    public Exclusions http(@RegExp String path, HttpMethod... methods) {
        if (methods.length == 0) {
            throw new IllegalArgumentException("Can not create exclusion without http methods!");
        }

        Collection<Exclusion> httpExclusions = exclusions.computeIfAbsent(Scheme.HTTP, s -> new ArrayList<>());

        synchronized (httpExclusions) {
            for (Exclusion exclusion : httpExclusions) {
                if (!(exclusion instanceof Exclusion.HttpExclusion httpExclusion)) {
                    throw new IllegalStateException("Found a non http exclusion "
                            + exclusion.getClass().getName() + " in the http list!");
                }

                if (exclusion.path().pattern().equals(path) &&
                        httpExclusion.methods().containsAll(Arrays.asList(HttpMethod.normalize(methods)))) {
                    return this;
                }
            }

            httpExclusions.add(new Exclusion.HttpExclusion(path, methods));
        }

        return this;
    }

    /**
     * Checks whether the given HTTP request is excluded from
     * authentication.
     *
     * @param path   The request path to evaluate.
     * @param method The HTTP method of the request.
     * @return {@code true} if the request matches an exclusion rule,
     * otherwise {@code false}.
     */
    public boolean isHttpExcluded(String path, HttpMethod method) {
        Collection<Exclusion> httpExclusions = exclusions.get(Scheme.HTTP);
        if (httpExclusions == null) {
            return false;
        }

        synchronized (httpExclusions) {
            for (Exclusion exclusion : httpExclusions) {
                if (!(exclusion instanceof Exclusion.HttpExclusion httpExclusion)) {
                    throw new IllegalStateException("Found a non http exclusion "
                            + exclusion.getClass().getName() + " in the http list!");
                }

                Matcher matcher = exclusion.path().matcher(path);
                if (!matcher.matches()) {
                    continue;
                }

                if (httpExclusion.methods().contains(method)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Registers a new WebSocket exclusion rule.
     * <p>
     * The exclusion is only added if no identical path rule already exists.
     *
     * @param path The regex path used to match websocket connections.
     * @return This {@link Exclusions} instance for chaining.
     */
    public Exclusions webSocket(@RegExp String path) {
        Collection<Exclusion> webSocketExclusions = exclusions.computeIfAbsent(Scheme.WS, s -> new ArrayList<>());

        synchronized (webSocketExclusions) {
            for (Exclusion exclusion : webSocketExclusions) {
                if (!(exclusion instanceof Exclusion.WebSocketExclusion)) {
                    throw new IllegalStateException("Found a non web socket exclusion "
                            + exclusion.getClass().getName() + " in the web socket list!");
                }

                if (exclusion.path().pattern().equals(path)) {
                    return this;
                }
            }

            webSocketExclusions.add(new Exclusion.WebSocketExclusion(path));
        }

        return this;
    }

    /**
     * Checks whether the given WebSocket connection path is
     * excluded from authentication.
     *
     * @param path The websocket connection path.
     * @return {@code true} if the path matches an exclusion rule,
     * otherwise {@code false}.
     */
    public boolean isWebSocketExcluded(String path) {
        Collection<Exclusion> httpExclusions = exclusions.get(Scheme.WS);
        if (httpExclusions == null) {
            return false;
        }

        synchronized (httpExclusions) {
            for (Exclusion exclusion : httpExclusions) {
                if (!(exclusion instanceof Exclusion.WebSocketExclusion)) {
                    throw new IllegalStateException("Found a non web socket exclusion "
                            + exclusion.getClass().getName() + " in the web socket list!");
                }

                Matcher matcher = exclusion.path().matcher(path);
                if (matcher.matches()) {
                    return true;
                }
            }
        }

        return false;
    }

}
