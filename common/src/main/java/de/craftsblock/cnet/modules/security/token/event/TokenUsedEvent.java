package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

public final class TokenUsedEvent extends TokenEvent {

    public TokenUsedEvent(Token token) {
        super(token);
    }

}
