package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftsnet.api.BaseExchange;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import org.jetbrains.annotations.NotNull;

/**
 * Event fired when a {@link Token} is actively used for authentication.
 * <p>
 * This event is triggered whenever a token is validated and accepted
 * during an authentication process, such as HTTP or WebSocket authentication.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class TokenUsedEvent extends TokenEvent {

    private final BaseExchange exchange;

    /**
     * Creates a new token usage event.
     *
     * @param token    The token that has been used for authentication
     * @param exchange The exchange that has been authenticated
     */
    public TokenUsedEvent(@NotNull Token token, @NotNull BaseExchange exchange) {
        super(token);

        this.exchange = exchange;
    }

    /**
     * Returns the exchange that has been authenticated.
     *
     * @return The exchange that has been authenticated
     */
    public @NotNull BaseExchange getExchange() {
        return exchange;
    }

    /**
     * Returns {@code true} if the exchange that has been
     * authenticated is in the context of an http call.
     *
     * @return {@code true} if the context is inside an http call.
     */
    public boolean isHttp() {
        return this.exchange instanceof Exchange;
    }

    /**
     * Returns {@code true} if the exchange that has been
     * authenticated is in the context of a websocket call.
     *
     * @return {@code true} if the context is inside a websocket call.
     */
    public boolean isWebsocket() {
        return this.exchange instanceof SocketExchange;
    }

}
