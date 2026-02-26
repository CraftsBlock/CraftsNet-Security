package de.craftsblock.cnet.modules.security.token.group;

import org.jetbrains.annotations.ApiStatus;

import java.util.List;

@ApiStatus.Internal
record GroupRequest(List<String> groups) {
}
