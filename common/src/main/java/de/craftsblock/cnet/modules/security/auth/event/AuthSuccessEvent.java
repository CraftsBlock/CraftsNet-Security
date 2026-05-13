package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.BaseExchange;

/**
 * Event fired whenever an authentication process completes successfully.
 * <p>
 * This event indicates that all authentication adapters within the
 * authentication chain approved the processed exchange.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthResultEvent
 * @see AuthResult
 * @since 1.0.0
 */
public final class AuthSuccessEvent extends AuthResultEvent {

    /**
     * Creates a new {@link AuthSuccessEvent}.
     *
     * @param exchange The successfully authenticated exchange.
     * @param result   The produced success result.
     */
    public AuthSuccessEvent(BaseExchange exchange, AuthResult result) {
        super(exchange, result);
    }

}