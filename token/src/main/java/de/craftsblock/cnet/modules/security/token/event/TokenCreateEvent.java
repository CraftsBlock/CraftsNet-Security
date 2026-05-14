package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

/**
 * Event fired when a new {@link Token} is created inside the security module.
 * <p>
 * This event is typically triggered by the
 * {@link de.craftsblock.cnet.modules.security.token.TokenManager TokenManager}
 * after a token has been generated but before or during persistence.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class TokenCreateEvent extends TokenEvent {

    /**
     * Creates a new token creation event.
     *
     * @param token The newly created token
     */
    public TokenCreateEvent(Token token) {
        super(token);
    }

}
