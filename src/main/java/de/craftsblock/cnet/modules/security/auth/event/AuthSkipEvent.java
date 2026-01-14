package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.BaseExchange;

public final class AuthSkipEvent extends AuthResultEvent {

    public AuthSkipEvent(BaseExchange exchange, AuthResult result) {
        super(exchange, result);
    }

}
