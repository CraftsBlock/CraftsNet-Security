package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

public final class TokenPersistEvent extends TokenEvent {

    public TokenPersistEvent(Token token) {
        super(token);
    }

}
