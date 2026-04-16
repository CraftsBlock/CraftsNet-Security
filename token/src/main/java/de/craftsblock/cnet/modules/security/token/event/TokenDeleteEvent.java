package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.event.TokenEvent;

public final class TokenDeleteEvent extends TokenEvent {

    public TokenDeleteEvent(Token token) {
        super(token);
    }

}
