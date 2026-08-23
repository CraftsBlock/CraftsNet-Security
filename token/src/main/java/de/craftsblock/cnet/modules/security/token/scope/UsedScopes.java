package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.craftscore.cache.LruCache;
import de.craftsblock.craftsnet.api.RouteRegistry;

import java.util.*;

/**
 * Represents the scopes that were successfully validated and consumed
 * during request or WebSocket authentication.
 * <p>
 * Once a {@link UsedScopes} has been validated against a token,
 * its values are stored as {@code UsedScopes} in the execution context
 * to allow later middleware or listeners to access the resolved scope set.
 *
 * @param scopes The collection of scopes that were successfully matched
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record UsedScopes(Collection<String> scopes) {

    private static final Class<RequireScope> ANNOTATION = RequireScope.class;

    private static LruCache<RouteRegistry.EndpointMapping, List<String>> scopeCache = new LruCache<>(50);

    /**
     * Converts a given list of {@link RouteRegistry.EndpointMapping} to a {@link UsedScopes}
     * which contains all the required scopes.
     *
     * @param mappings The {@link RouteRegistry.EndpointMapping} to convert.
     * @return A {@link UsedScopes} which contains the required scopes.
     * @since 1.0.2
     */
    static UsedScopes fromMappings(Collection<RouteRegistry.EndpointMapping> mappings) {
        Set<String> scopes = new HashSet<>(mappings.size());

        for (RouteRegistry.EndpointMapping mapping : mappings) {
            List<String> required = mappingToScopes(mapping);
            if (required.isEmpty()) {
                continue;
            }

            scopes.addAll(required);
        }

        return new UsedScopes(List.copyOf(scopes));
    }

    /**
     * Converts a given {@link RouteRegistry.EndpointMapping} to a list of
     * required scopes.
     *
     * @param mapping The {@link RouteRegistry.EndpointMapping} to convert.
     * @return The list of required scopes.
     * @since 1.0.2
     */
    private static List<String> mappingToScopes(RouteRegistry.EndpointMapping mapping) {
        if (scopeCache.containsKey(mapping)) {
            return scopeCache.get(mapping);
        }

        if (mapping.isPresent(ANNOTATION, "value")) {
            List<String> scopes = mapping.getRequirements(ANNOTATION, "value");
            scopeCache.put(mapping, scopes);
            return scopes;
        }

        return Collections.emptyList();
    }

    /**
     * Sets the internal {@link LruCache} instance for caching resolved scopes.
     *
     * @param scopeCache The {@link LruCache} for caching.
     * @since 1.0.2
     */
    public static void setCache(LruCache<RouteRegistry.EndpointMapping, List<String>> scopeCache) {
        UsedScopes.scopeCache = scopeCache;
    }

}
