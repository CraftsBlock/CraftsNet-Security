package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftscore.event.Event;
import de.craftsblock.craftsnet.api.BaseExchange;

public abstract sealed class AuthResultEvent extends Event
        permits AuthFailureEvent, AuthSkipEvent, AuthSuccessEvent {

    private final BaseExchange exchange;
    private final AuthResult result;

    public AuthResultEvent(BaseExchange exchange, AuthResult result) {
        this.exchange = exchange;
        this.result = result;
    }

    public BaseExchange getExchange() {
        return exchange;
    }

    public AuthResult getResult() {
        return result;
    }

}
