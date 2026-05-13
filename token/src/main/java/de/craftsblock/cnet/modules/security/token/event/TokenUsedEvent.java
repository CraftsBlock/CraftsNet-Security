package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

/**
 * Event fired when a {@link Token} is actively used for authentication.
 * <p>
 * This event is triggered whenever a token is validated and accepted
 * during an authentication process, such as HTTP or WebSocket authentication.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class TokenUsedEvent extends TokenEvent {

    /**
     * Creates a new token usage event.
     *
     * @param token The token that has been used for authentication
     */
    public TokenUsedEvent(Token token) {
        super(token);
    }

}
