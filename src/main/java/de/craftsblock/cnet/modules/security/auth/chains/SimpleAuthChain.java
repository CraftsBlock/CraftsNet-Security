package de.craftsblock.cnet.modules.security.auth.chains;

import de.craftsblock.cnet.modules.security.auth.AuthAdapter;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.http.Request;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * The {@link SimpleAuthChain} class is a concrete implementation of the {@link AuthChain} class,
 * using a simple queue-based approach to handle multiple {@link AuthAdapter} instances in sequence.
 * It processes each authentication adapter in the order they were added.
 *
 * <p>Adapters are executed in the order they were appended to the chain, and the chain stops
 * processing if an authentication result is cancelled (i.e., if an adapter denies access).</p>
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.1.0
 * @since 1.0.0-SNAPSHOT
 */
public class SimpleAuthChain extends AuthChain {

    private final ConcurrentLinkedQueue<AuthAdapter> adapters = new ConcurrentLinkedQueue<>();
    private final List<Exclusion> exclusions = new ArrayList<>();

    /**
     * Authenticates the provided {@link Exchange} by passing it through the chain of
     * registered {@link AuthAdapter} instances. If any adapter in the chain cancels the
     * authentication, the process stops.
     *
     * @param exchange The {@link Exchange} object representing the incoming HTTP request.
     * @return The {@link AuthResult} object that contains the result of the authentication process.
     */
    @Override
    public AuthResult authenticate(final Exchange exchange) {
        final Request request = exchange.request();
        final AuthResult result = new AuthResult();

        if (exclusions.stream().anyMatch(exclusion -> exclusion.isExcluded(request)))
            return result;

        // Iterate over each adapter in the chain and authenticate the request.
        for (AuthAdapter adapter : adapters) {
            adapter.authenticate(result, exchange);

            // Stop processing further adapters if the authentication is cancelled.
            if (result.isCancelled()) break;
        }

        return result;
    }

    /**
     * Appends a new {@link AuthAdapter} to the chain. If the adapter is already present,
     * it will not be added again.
     *
     * @param adapter The {@link AuthAdapter} to be appended to the chain.
     * @return The instance of {@link SimpleAuthChain} used for chain method calls.
     */
    @Override
    public SimpleAuthChain append(AuthAdapter adapter) {
        if (!adapters.isEmpty() && adapters.contains(adapter)) return this;
        adapters.add(adapter);
        return this;
    }

    /**
     * Removes a specific {@link AuthAdapter} from the chain.
     *
     * @param adapter The {@link AuthAdapter} to be removed from the chain.
     * @return The instance of {@link SimpleAuthChain} used for chain method calls.
     */
    @Override
    public SimpleAuthChain remove(AuthAdapter adapter) {
        adapters.remove(adapter);
        return this;
    }

    /**
     * Removes all instances of the specified {@link AuthAdapter} class from the chain.
     *
     * @param adapter The class type of the {@link AuthAdapter} to be removed.
     * @return The instance of {@link SimpleAuthChain} used for chain method calls.
     */
    @Override
    public SimpleAuthChain removeAll(Class<? extends AuthAdapter> adapter) {
        adapters.stream()
                .filter(adapter::isInstance)
                .forEach(this::remove);
        return this;
    }

    /**
     * Adds an url pattern to be excluded from authentication.
     *
     * @param pattern A regular expression matching request urls to exclude.
     * @return The instance of {@link SimpleAuthChain} used for chain method calls.
     */
    public SimpleAuthChain addExclusion(String pattern) {
        return addExclusion(pattern, HttpMethod.ALL);
    }

    /**
     * Adds an url pattern to be excluded from authentication for the specified http methods.
     *
     * @param pattern A regular expression matching request URLs to exclude.
     * @param methods One or more {@link HttpMethod methods} for which the pattern should be excluded.
     * @return The instance of {@link SimpleAuthChain} used for chain method calls.
     */
    public SimpleAuthChain addExclusion(String pattern, HttpMethod... methods) {
        exclusions.add(new Exclusion(pattern, normalizedMethods(methods)));
        return this;
    }

    /**
     * Removes all exclusion entries matching the given url pattern.
     * <p>Any {@link Exclusion} whose pattern equals the provided {@code pattern} will be removed</p>
     *
     * @param pattern The regular expression pattern of request URLs to remove from exclusions
     * @return The current {@link SimpleAuthChain} instance, to allow method chaining
     */
    public SimpleAuthChain removeExclusion(String pattern) {
        return removeExclusion(pattern, HttpMethod.ALL);
    }

    /**
     * Removes exclusion entries matching the given url pattern for the specified http methods.
     * <p>If an {@link Exclusion} with the same pattern exists and any of its methods matches one of
     * the provided {@code methods}, that exclusion entry will be removed from the list.</p>
     *
     * @param pattern The regular expression pattern of request URLs to remove from exclusions
     * @param methods One or more {@link HttpMethod methods} for which the pattern should no longer be excluded
     * @return The current {@link SimpleAuthChain} instance, to allow method chaining
     */
    public SimpleAuthChain removeExclusion(String pattern, HttpMethod... methods) {
        exclusions.removeIf(exclusion -> {
            if (!exclusion.pattern().equals(pattern)) return false;

            Collection<HttpMethod> excludedMethods = Arrays.asList(exclusion.methods());
            return Arrays.stream(methods).anyMatch(excludedMethods::contains);
        });
        return this;
    }

    /**
     * Expands any composite {@link HttpMethod methods} into their
     * constituent methods and returns a flat array of real methods.
     *
     * @param methods One or more {@link HttpMethod}s, possibly composite, to normalize.
     * @return An array of individual {@link HttpMethod}s after expansion.
     */
    private HttpMethod[] normalizedMethods(HttpMethod... methods) {
        Set<HttpMethod> realMethods = new HashSet<>();

        for (HttpMethod method : methods)
            switch (method) {
                case ALL, ALL_RAW -> {
                    List<HttpMethod> subMethods = Arrays.stream(method.getMethods()).map(HttpMethod::parse).toList();
                    realMethods.addAll(subMethods);
                }
                default -> realMethods.add(method);
            }

        return realMethods.toArray(HttpMethod[]::new);
    }

    /**
     * Internal record representing a URL pattern exclusion for one or more HTTP methods.
     *
     * @param pattern A regular expression for matching request URLs.
     * @param methods The HTTP methods for which the pattern is excluded.
     * @author Philipp Maywald
     * @author CraftsBlock
     * @version 1.0.0
     * @see HttpMethod
     * @since 1.0.0-SNAPSHOT
     */
    private record Exclusion(String pattern, HttpMethod... methods) {

        /**
         * Checks whether the given {@link Request} matches this exclusion.
         *
         * @param request The incoming HTTP request to check.
         * @return {@code true} if the request’s URL and method match this exclusion.
         */
        boolean isExcluded(Request request) {
            return isExcluded(request.getUrl(), request.getHttpMethod());
        }

        /**
         * Checks whether the given URL and {@link HttpMethod} match this exclusion.
         *
         * @param url    The request URL to match against the exclusion pattern.
         * @param method The HTTP method to check for exclusion.
         * @return {@code true} if the URL matches the pattern and the method is in the exclusion list.
         */
        boolean isExcluded(String url, HttpMethod method) {
            if (!url.matches(pattern)) return false;
            return Arrays.asList(methods).contains(method);
        }

    }

}
