package de.craftsblock.cnet.modules.security.token.scope;

import org.jetbrains.annotations.ApiStatus;

import java.util.List;

@ApiStatus.Internal
record ScopeResult(List<String> scopes, boolean allScopesPresent) {
}
