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

sealed interface AuthListener<T> permits PreRequestListener, WebSocketConnectListener {

    CraftsNetSecurity addon();

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
