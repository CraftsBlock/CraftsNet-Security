package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftscore.event.Event;

/**
 * Base event for all token-related lifecycle actions inside the security module.
 * <p>
 * This event is fired whenever a {@link Token} is created, persisted, deleted,
 * or actively used within the system. It provides a unified abstraction for
 * reacting to token state changes across the security framework.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public abstract sealed class TokenEvent extends Event
        permits TokenCreateEvent, TokenDeleteEvent, TokenPersistEvent, TokenUsedEvent {

    private final Token token;

    /**
     * Creates a new token event for the given token instance.
     *
     * @param token The token associated with this event
     */
    public TokenEvent(Token token) {
        this.token = token;
    }

    /**
     * Returns the token associated with this event.
     *
     * @return The affected {@link Token}
     */
    public Token getToken() {
        return token;
    }

    /**
     * Token events must always be processed synchronously to ensure
     * consistent security state across the authentication system.
     *
     * @return {@code false}, as asynchronous execution is not allowed
     */
    @Override
    protected boolean isAsyncAllowed() {
        return false;
    }

}
