package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftscore.event.Event;

public abstract sealed class TokenEvent extends Event
        permits TokenCreateEvent, TokenDeleteEvent, TokenPersistEvent, TokenUsedEvent {

    private final Token token;

    public TokenEvent(Token token) {
        this.token = token;
    }

    public Token getToken() {
        return token;
    }

}
