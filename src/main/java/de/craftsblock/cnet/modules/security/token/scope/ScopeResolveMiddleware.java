package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftscore.event.CancellableEvent;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.BaseExchange;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.EventWithCancelReason;
import de.craftsblock.craftsnet.events.requests.routes.RouteRequestEvent;
import de.craftsblock.craftsnet.events.sockets.message.IncomingSocketMessageEvent;
import org.jetbrains.annotations.ApiStatus;

import java.util.function.Consumer;

@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class ScopeResolveMiddleware implements ListenerAdapter {

    private final Json MISSING_SCOPES_MESSAGE = Json.empty()
            .set("success", false)
            .set("error.code", 403)
            .set("error.message", "Not allowed!");

    private <T> void handle(BaseExchange exchange, CancellableEvent event, T subject, Consumer<T> onFailure) {
        Context context = exchange.context();
        System.out.println(context);
        if (context == null || !context.containsKey(ScopeRequest.class)) {
            return;
        }

        if (!context.containsKey(Token.class)) {
            event.setCancelled(true);
            if (event instanceof EventWithCancelReason withCancelReason) {
                withCancelReason.setCancelReason("NO TOKEN");
            }

            return;
        }

        final Token token = context.getTyped(Token.class);
        final ScopeRequest result = context.getTyped(ScopeRequest.class);
        if (token.scopes().containsAll(result.scopes())) {
            return;
        }

        event.setCancelled(true);
        if (event instanceof EventWithCancelReason withCancelReason) {
            withCancelReason.setCancelReason("AUTH FAILED");
        }

        onFailure.accept(subject);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreWhenCancelled = true)
    public void handleRequest(RouteRequestEvent event) {
        final Exchange exchange = event.getExchange();
        handle(exchange, event, exchange.response(), response -> response.print(MISSING_SCOPES_MESSAGE));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreWhenCancelled = true)
    public void handleWebSocketMessage(IncomingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        handle(exchange, event, exchange.client(), client -> {
            client.sendMessage(MISSING_SCOPES_MESSAGE);
            client.close(ClosureCode.NORMAL, "Not allowed!");
        });
    }

}
