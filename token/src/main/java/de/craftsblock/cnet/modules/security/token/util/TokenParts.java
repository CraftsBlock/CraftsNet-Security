package de.craftsblock.cnet.modules.security.token.util;

public record TokenParts(String prefix, long id, byte[] secret) {
}
