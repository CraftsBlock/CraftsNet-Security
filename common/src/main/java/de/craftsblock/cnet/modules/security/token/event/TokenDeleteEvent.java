package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

public final class TokenDeleteEvent extends TokenEvent {

    public TokenDeleteEvent(Token token) {
        super(token);
    }

}
