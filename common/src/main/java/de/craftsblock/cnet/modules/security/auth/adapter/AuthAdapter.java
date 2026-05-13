package de.craftsblock.cnet.modules.security.auth.adapter;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;

/**
 * Represents a generic authentication adapter that can participate
 * in the authentication chain system.
 * <p>
 * Authentication adapters are responsible for validating incoming
 * requests or websocket connections and returning an appropriate
 * {@link AuthResult}.
 * <p>
 * Depending on the implemented sub-interface, an adapter may support
 * HTTP authentication, websocket authentication, or both.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public sealed interface AuthAdapter permits AuthAdapter.Http, AuthAdapter.WebSocket {

    /**
     * Represents an authentication adapter that handles
     * HTTP request authentication.
     *
     * @author Philipp Maywald
     * @author CraftsBlock
     */
    non-sealed interface Http extends AuthAdapter {

        /**
         * Authenticates the given HTTP exchange.
         *
         * @param exchange The HTTP exchange to authenticate.
         * @return The resulting {@link AuthResult}.
         */
        AuthResult authenticate(Exchange exchange);

    }

    /**
     * Represents an authentication adapter that handles
     * websocket authentication.
     *
     * @author Philipp Maywald
     * @author CraftsBlock
     */
    non-sealed interface WebSocket extends AuthAdapter {

        /**
         * Authenticates the given websocket exchange.
         *
         * @param exchange The websocket exchange to authenticate.
         * @return The resulting {@link AuthResult}.
         */
        AuthResult authenticate(SocketExchange exchange);

    }

}
