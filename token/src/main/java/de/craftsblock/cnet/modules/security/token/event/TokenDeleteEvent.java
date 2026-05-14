package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

/**
 * Event fired when a {@link Token} is deleted from the system.
 * <p>
 * This event is triggered after a token has been removed from the underlying
 * storage and cache, allowing listeners to react to invalidation.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class TokenDeleteEvent extends TokenEvent {

    /**
     * Creates a new token deletion event.
     *
     * @param token The token that has been deleted
     */
    public TokenDeleteEvent(Token token) {
        super(token);
    }

}
