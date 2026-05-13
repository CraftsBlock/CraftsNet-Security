package de.craftsblock.cnet.modules.security.token.group;

import java.util.Collection;

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
}
