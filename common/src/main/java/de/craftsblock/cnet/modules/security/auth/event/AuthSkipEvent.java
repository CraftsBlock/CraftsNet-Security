package de.craftsblock.cnet.modules.security.auth.event;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.craftsnet.api.BaseExchange;

/**
 * Event fired whenever an authentication process is skipped.
 * <p>
 * This usually occurs when the processed exchange matches
 * an authentication exclusion rule configured within the
 * authentication chain.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthResultEvent
 * @see AuthResult
 * @since 1.0.0
 */
public final class AuthSkipEvent extends AuthResultEvent {

    /**
     * Creates a new {@link AuthSkipEvent}.
     *
     * @param exchange The exchange for which authentication was skipped.
     * @param result   The produced skip result.
     */
    public AuthSkipEvent(BaseExchange exchange, AuthResult result) {
        super(exchange, result);
    }

}