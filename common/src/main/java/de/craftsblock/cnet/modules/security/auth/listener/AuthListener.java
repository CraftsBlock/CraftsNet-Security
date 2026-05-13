package de.craftsblock.cnet.modules.security.auth.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.event.AuthFailureEvent;
import de.craftsblock.cnet.modules.security.auth.event.AuthSkipEvent;
import de.craftsblock.cnet.modules.security.auth.event.AuthSuccessEvent;
import de.craftsblock.craftscore.event.CancellableEvent;
import de.craftsblock.craftsnet.api.BaseExchange;
import de.craftsblock.craftsnet.events.EventWithCancelReason;

import java.util.function.BiConsumer;

/**
 * Shared base contract for authentication related listeners.
 * <p>
 * Implementations of this interface provide common authentication
 * handling logic for different exchange types such as HTTP requests
 * and websocket connections.
 * <p>
 * The interface automatically executes the global authentication
 * chain, dispatches authentication result events, and handles
 * request cancellation on authentication failure.
 *
 * @param <T> The subject type associated with the authentication process.
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthResult
 * @see AuthFailureEvent
 * @see AuthSuccessEvent
 * @see AuthSkipEvent
 * @since 1.0.0
 */
sealed interface AuthListener<T> permits PreRequestListener, WebSocketConnectListener {

    /**
     * Retrieves the active security addon instance.
     *
     * @return The active {@link CraftsNetSecurity} instance.
     */
    CraftsNetSecurity addon();

    /**
     * Executes the authentication process for the given exchange.
     * <p>
     * Depending on the produced {@link AuthResult}, this method
     * either dispatches a success or skip event, or cancels the
     * provided event and invokes the given failure handler.
     *
     * @param exchange  The exchange to authenticate.
     * @param event     The cancellable event associated with the exchange.
     * @param subject   The subject associated with the authentication process.
     * @param onFailure The callback invoked when authentication fails.
     */
    default void authenticate(BaseExchange exchange, CancellableEvent event, T subject, BiConsumer<T, AuthResult> onFailure) {
        CraftsNetSecurity addon = this.addon();
        AuthResult result = CraftsNetSecurity.getAuthChain().authenticate(exchange);

        if (!result.isFailure()) {
            addon.getListenerRegistry().call(
                    result.isOk()
                            ? new AuthSuccessEvent(exchange, result)
                            : new AuthSkipEvent(exchange, result)
            );
            return;
        }

        event.setCancelled(true);
        if (event instanceof EventWithCancelReason withCancelReason) {
            withCancelReason.setCancelReason("AUTH FAILED");
        }

        addon.getListenerRegistry().call(new AuthFailureEvent(exchange, result));
        onFailure.accept(subject, result);
    }

}
