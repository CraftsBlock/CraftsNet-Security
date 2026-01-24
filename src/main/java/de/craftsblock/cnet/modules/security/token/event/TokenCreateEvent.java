package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

public final class TokenCreateEvent extends TokenEvent {

    public TokenCreateEvent(Token token) {
        super(token);
    }

}
