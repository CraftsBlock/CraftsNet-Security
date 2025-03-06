package de.craftsblock.cnet.modules.security.auth.token.adapter;

/**
 * Enum representing the supported types of token authentication.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @since 1.0.0-SNAPSHOT
 */
public enum TokenAuthType {

    /**
     * Token authentication via HTTP header.
     */
    HEADER,

    /**
     * Token authentication via HTTP cookie.
     */
    COOKIE,

    /**
     * Token authentication via session attribute.
     */
    SESSION,

}
