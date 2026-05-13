package de.craftsblock.cnet.modules.security.token.scope;

import java.util.Collection;

/**
 * Represents the scopes that were successfully validated and consumed
 * during request or WebSocket authentication.
 * <p>
 * Once a {@link ScopeRequest} has been validated against a token,
 * its values are stored as {@code UsedScopes} in the execution context
 * to allow later middleware or listeners to access the resolved scope set.
 *
 * @param scopes The collection of scopes that were successfully matched
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record UsedScopes(Collection<String> scopes) {
}
