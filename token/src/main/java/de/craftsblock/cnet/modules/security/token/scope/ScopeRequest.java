package de.craftsblock.cnet.modules.security.token.scope;

import org.jetbrains.annotations.ApiStatus;

import java.util.List;

/**
 * Internal data holder used to transport required scope definitions
 * through the request or socket context.
 * <p>
 * This record is injected by {@link ScopeRequirement} during route
 * resolution and later consumed by {@link ScopeResolveMiddleware}
 * to validate whether an authenticated token satisfies all required scopes.
 *
 * @param scopes The list of scopes required for the current request
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
record ScopeRequest(List<String> scopes) {
}
