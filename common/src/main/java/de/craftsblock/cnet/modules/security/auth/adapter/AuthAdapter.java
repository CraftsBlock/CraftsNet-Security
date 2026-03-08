package de.craftsblock.cnet.modules.security.auth.adapter;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;

public sealed interface AuthAdapter permits AuthAdapter.Http, AuthAdapter.WebSocket {

    non-sealed interface Http extends AuthAdapter {

        AuthResult authenticate(Exchange exchange);

    }

    non-sealed interface WebSocket extends AuthAdapter {

        AuthResult authenticate(SocketExchange exchange);

    }

}
