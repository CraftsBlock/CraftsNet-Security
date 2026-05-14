package de.craftsblock.cnet.modules.security.token.util;

/**
 * Represents the decomposed parts of a serialized authentication token.
 * <p>
 * A token is typically structured into a prefix, an identifier, and a
 * cryptographic secret. This record holds the parsed representation of
 * those components after decoding.
 *
 * @param prefix The token prefix used to identify the system or issuer
 * @param id     The numeric identifier encoded in hexadecimal form
 * @param secret The raw secret bytes used for authentication validation
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record TokenParts(String prefix, long id, byte[] secret) {
}
