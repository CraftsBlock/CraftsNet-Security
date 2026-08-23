package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.craftscore.cache.LruCache;
import de.craftsblock.craftsnet.api.RouteRegistry;

import java.util.*;

/**
 * Represents a collection of groups that were effectively resolved and used
 * during authorization or request processing.
 * <p>
 * This record is typically used as a final resolved view of group information
 * after evaluation of group requirements and token-based group membership.
 *
 * @param groups the resolved collection of group names
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record UsedGroups(Collection<String> groups) {

    private static final Class<RequireGroup> ANNOTATION = RequireGroup.class;

    private static LruCache<RouteRegistry.EndpointMapping, List<String>> groupCache = new LruCache<>(50);

    /**
     * Converts a given list of {@link RouteRegistry.EndpointMapping} to a {@link UsedGroups}
     * which contains all the required groups.
     *
     * @param mappings The {@link RouteRegistry.EndpointMapping} to convert.
     * @return A {@link UsedGroups} which contains the required groups.
     * @since 1.0.2
     */
    static UsedGroups fromMappings(Collection<RouteRegistry.EndpointMapping> mappings) {
        Set<String> groups = new HashSet<>(mappings.size());

        for (RouteRegistry.EndpointMapping mapping : mappings) {
            List<String> required = mappingToGroups(mapping);
            if (required.isEmpty()) {
                continue;
            }

            groups.addAll(required);
        }

        return new UsedGroups(List.copyOf(groups));
    }

    /**
     * Converts a given {@link RouteRegistry.EndpointMapping} to a list of
     * required groups.
     *
     * @param mapping The {@link RouteRegistry.EndpointMapping} to convert.
     * @return The list of required groups.
     * @since 1.0.2
     */
    private static List<String> mappingToGroups(RouteRegistry.EndpointMapping mapping) {
        if (groupCache.containsKey(mapping)) {
            return groupCache.get(mapping);
        }

        if (mapping.isPresent(ANNOTATION, "value")) {
            List<String> groups = mapping.getRequirements(ANNOTATION, "value");
            groupCache.put(mapping, groups);
            return groups;
        }

        return Collections.emptyList();
    }

    /**
     * Sets the internal {@link LruCache} instance for caching resolved groups.
     *
     * @param groupCache The {@link LruCache} for caching.
     * @since 1.0.2
     */
    public static void setCache(LruCache<RouteRegistry.EndpointMapping, List<String>> groupCache) {
        UsedGroups.groupCache = groupCache;
    }

}
