package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftscore.event.Event;
import de.craftsblock.craftsnet.api.BaseExchange;

/**
 * Base event for all authentication result related events.
 * <p>
 * This event is fired after an authentication process has been
 * completed and provides access to both the processed
 * {@link BaseExchange} and the produced {@link AuthResult}.
 * <p>
 * Concrete subclasses represent specific authentication states
 * such as successful, skipped, or failed authentication attempts.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthResult
 * @see AuthFailureEvent
 * @see AuthSkipEvent
 * @see AuthSuccessEvent
 * @since 1.0.0
 */
public abstract sealed class AuthResultEvent extends Event
        permits AuthFailureEvent, AuthSkipEvent, AuthSuccessEvent {

    private final BaseExchange exchange;
    private final AuthResult result;

    /**
     * Creates a new authentication result event.
     *
     * @param exchange The exchange that was authenticated.
     * @param result   The produced authentication result.
     */
    public AuthResultEvent(BaseExchange exchange, AuthResult result) {
        this.exchange = exchange;
        this.result = result;
    }

    /**
     * Retrieves the exchange associated with this authentication event.
     *
     * @return The authenticated exchange.
     */
    public BaseExchange getExchange() {
        return exchange;
    }

    /**
     * Retrieves the authentication result associated with this event.
     *
     * @return The authentication result.
     */
    public AuthResult getResult() {
        return result;
    }

    /**
     * Authentication result events are always executed synchronously.
     * <p>
     * {@inheritDoc}
     * </p>
     *
     * @return {@inheritDoc}
     */
    @Override
    protected boolean isAsyncAllowed() {
        return false;
    }

}
