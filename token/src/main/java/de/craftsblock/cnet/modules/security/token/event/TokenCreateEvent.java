package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.event.TokenEvent;

public final class TokenCreateEvent extends TokenEvent {

    public TokenCreateEvent(Token token) {
        super(token);
    }

}
