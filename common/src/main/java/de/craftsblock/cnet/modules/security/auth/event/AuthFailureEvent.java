package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.BaseExchange;

/**
 * Event fired whenever an authentication process fails.
 * <p>
 * This event provides access to the authenticated exchange
 * as well as the failure {@link AuthResult} that caused
 * the authentication process to abort.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthResultEvent
 * @see AuthResult
 * @since 1.0.0
 */
public final class AuthFailureEvent extends AuthResultEvent {

    /**
     * Creates a new {@link AuthFailureEvent}.
     *
     * @param exchange The exchange that failed authentication.
     * @param result   The produced failure result.
     */
    public AuthFailureEvent(BaseExchange exchange, AuthResult result) {
        super(exchange, result);
    }

}
