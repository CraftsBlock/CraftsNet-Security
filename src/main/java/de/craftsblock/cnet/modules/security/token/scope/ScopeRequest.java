package de.craftsblock.cnet.modules.security.token.scope;

import org.jetbrains.annotations.ApiStatus;

import java.util.List;

@ApiStatus.Internal
record ScopeRequest(List<String> scopes) {
}
