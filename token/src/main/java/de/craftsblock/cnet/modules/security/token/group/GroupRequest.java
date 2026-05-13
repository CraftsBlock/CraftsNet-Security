package de.craftsblock.cnet.modules.security.token.group;

import org.jetbrains.annotations.ApiStatus;

import java.util.List;

/**
 * Internal request wrapper used during route processing to transport
 * group requirements extracted from endpoint metadata.
 * <p>
 * This record is typically injected by {@link de.craftsblock.cnet.modules.security.token.group.GroupRequirement}
 * implementations and represents the configured group names that are required
 * to access a specific route or websocket endpoint.
 *
 * @param groups the list of required group names associated with the request
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
record GroupRequest(List<String> groups) {
}
