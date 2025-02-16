package de.craftsblock.cnet.modules.security.events.auth;

import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.http.Response;
import de.craftsblock.craftsnet.api.session.Session;
import org.jetbrains.annotations.NotNull;

/**
 * Represents a base class for authentication related events that involve
 * an HTTP {@link Exchange}. This class provides access to the request,
 * response, and session storage associated with the exchange.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @see Exchange
 * @see Request
 * @see Response
 * @see Session
 * @since 1.0.0-SNAPSHOT
 */
public abstract class GenericAuthResultEvent extends GenericAuthEvent {

    private final @NotNull Exchange exchange;

    /**
     * Constructs a new {@link GenericAuthResultEvent}.
     *
     * @param exchange The HTTP exchange associated with this event. Must not be null.
     * @throws NullPointerException If {@code exchange} is null.
     */
    public GenericAuthResultEvent(@NotNull Exchange exchange) {
        this.exchange = exchange;
    }

    /**
     * Gets the HTTP exchange associated with this event.
     *
     * @return The associated {@link Exchange}.
     */
    public @NotNull Exchange getExchange() {
        return exchange;
    }

    /**
     * Gets the HTTP request associated with this event.
     *
     * @return The associated {@link Request}.
     */
    public Request getRequest() {
        return exchange.request();
    }

    /**
     * Gets the HTTP response associated with this event.
     *
     * @return The associated {@link Response}.
     */
    public Response getResponse() {
        return exchange.response();
    }

    /**
     * Gets the session storage associated with this event.
     *
     * @return The associated {@link Session}.
     */
    public Session getStorage() {
        return exchange.session();
    }

}
