package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.BaseExchange;

public final class AuthSuccessEvent extends AuthResultEvent {

    public AuthSuccessEvent(BaseExchange exchange, AuthResult result) {
        super(exchange, result);
    }

}
