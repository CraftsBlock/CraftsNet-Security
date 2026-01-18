package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.BaseExchange;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.EventWithCancelReason;
import de.craftsblock.craftsnet.events.requests.routes.RouteRequestEvent;
import de.craftsblock.craftsnet.events.sockets.ClientConnectEvent;
import org.jetbrains.annotations.ApiStatus;

import java.util.function.Consumer;

@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class ScopeResolveMiddleware implements ListenerAdapter {

    private final Json MISSING_SCOPES_MESSAGE = Json.empty()
            .set("success", false)
            .set("error.code", 403)
            .set("error.message", "Not allowed!");

    private <T> void handle(BaseExchange exchange, EventWithCancelReason event, T subject, Consumer<T> onFailure) {
        Context context = exchange.context();
        if (context == null || !context.containsKey(ScopeResult.class)) {
            return;
        }

        try {
            final ScopeResult result = context.getTyped(ScopeResult.class);
            if (!result.allScopesPresent()) {
                event.setCancelled(true);
                event.setCancelReason("AUTH FAILED");

                onFailure.accept(subject);
            }
        } finally {
            context.remove(ScopeResult.class);
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleRequest(RouteRequestEvent event) {
        final Exchange exchange = event.getExchange();
        handle(exchange, event, exchange.response(), response -> response.print(MISSING_SCOPES_MESSAGE));
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleWebSocketConnect(ClientConnectEvent event) {
        final SocketExchange exchange = event.getExchange();
        handle(exchange, event, exchange.client(), client -> client.sendMessage(MISSING_SCOPES_MESSAGE));
    }

}
