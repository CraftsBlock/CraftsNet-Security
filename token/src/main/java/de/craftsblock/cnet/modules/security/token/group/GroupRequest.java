package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.craftscore.cache.LruCache;
import de.craftsblock.craftsnet.api.RouteRegistry;
import org.jetbrains.annotations.ApiStatus;

import javax.imageio.plugins.tiff.ExifInteroperabilityTagSet;
import java.util.*;

/**
 * Internal request wrapper used during route processing to transport
 * group requirements extracted from endpoint metadata.
 *
 * @param groups the list of required group names associated with the request
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
record GroupRequest(List<String> groups) {

    private static final Class<RequireGroup> ANNOTATION = RequireGroup.class;

    private static LruCache<RouteRegistry.EndpointMapping, List<String>> groupCache = new LruCache<>(50);

    /**
     * Converts a given list of {@link RouteRegistry.EndpointMapping} to a {@link GroupRequest}
     * which contains all the required groups.
     *
     * @param mappings The {@link RouteRegistry.EndpointMapping} to convert.
     * @return A {@link GroupRequest} which contains the required groups.
     * @since 1.0.2
     */
    static GroupRequest fromMappings(Collection<RouteRegistry.EndpointMapping> mappings) {
        Set<String> groups = new HashSet<>(mappings.size());

        for (RouteRegistry.EndpointMapping mapping : mappings) {
            List<String> required = mappingToGroups(mapping);
            if (required.isEmpty()) {
                continue;
            }

            groups.addAll(required);
        }

        return new GroupRequest(List.copyOf(groups));
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
        GroupRequest.groupCache = groupCache;
    }

}
