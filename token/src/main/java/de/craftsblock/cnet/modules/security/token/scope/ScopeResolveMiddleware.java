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
import de.craftsblock.craftsnet.api.http.status.HttpStatus;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.EventWithCancelReason;
import de.craftsblock.craftsnet.events.requests.routes.RouteRequestEvent;
import de.craftsblock.craftsnet.events.sockets.message.IncomingSocketMessageEvent;
import org.jetbrains.annotations.ApiStatus;

import java.util.Collections;
import java.util.function.Consumer;

/**
 * Middleware responsible for resolving and validating required scopes
 * that were injected into the request or socket context by {@link ScopeRequirement}.
 * <p>
 * This component runs inside the CraftsNet event pipeline and ensures that
 * authenticated tokens fulfill all declared scope requirements before
 * allowing request execution to continue.
 * <p>
 * If validation fails, the request or socket connection is rejected and
 * an error response is returned to the client.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class ScopeResolveMiddleware implements ListenerAdapter {

    private final Json MISSING_SCOPES_MESSAGE = Json.empty()
            .set("success", false)
            .set("error.code", HttpStatus.ClientError.BAD_REQUEST.getCode())
            .set("error.message", "Not allowed!");

    /**
     * Shared scope validation logic used for both HTTP and WebSocket
     * exchanges.
     * <p>
     * This method verifies whether the current exchange contains a valid
     * token and whether the token satisfies all required scopes defined
     * in the context.
     * <p>
     * If validation fails, the event is cancelled and the provided failure
     * handler is executed.
     *
     * @param exchange  The base exchange (HTTP or WebSocket)
     * @param event     The cancellable event being processed
     * @param subject   The subject passed to the failure callback
     * @param onFailure Callback executed when validation fails
     * @param <T>       The type of subject handled by the failure callback
     */
    private <T> void handle(BaseExchange exchange, CancellableEvent event, T subject, Consumer<T> onFailure) {
        Context context = exchange.context();
        if (context == null || !context.containsKey(ScopeRequest.class)) {
            return;
        }

        if (!context.containsKey(Token.class)) {
            event.setCancelled(true);
            if (event instanceof EventWithCancelReason withCancelReason) {
                withCancelReason.setCancelReason("NO TOKEN");
            }

            onFailure.accept(subject);
            return;
        }

        final Token token = context.getTyped(Token.class);
        final ScopeRequest result = context.getTyped(ScopeRequest.class);

        if (token.scopes().containsAll(result.scopes())) {
            context.remove(ScopeRequest.class);
            context.put(new UsedScopes(Collections.unmodifiableList(result.scopes())));
            return;
        }

        event.setCancelled(true);
        if (event instanceof EventWithCancelReason withCancelReason) {
            withCancelReason.setCancelReason("SCOPE MISMATCH");
        }

        onFailure.accept(subject);
    }

    /**
     * Handles HTTP route requests and applies scope validation logic.
     *
     * @param event The route request event
     */
    @EventHandler(priority = EventPriority.NORMAL, ignoreWhenCancelled = true)
    public void handleRequest(RouteRequestEvent event) {
        final Exchange exchange = event.getExchange();
        handle(exchange, event, exchange.response(), response -> {
            if (!response.headersSent()) {
                response.setStatus(HttpStatus.ClientError.BAD_REQUEST);
            }

            if (!response.sendingFile()) {
                response.print(MISSING_SCOPES_MESSAGE);
            }
        });
    }

    /**
     * Handles incoming WebSocket messages and applies scope validation logic.
     *
     * @param event The incoming socket message event
     */
    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleWebSocketMessage(IncomingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        handle(exchange, event, exchange.client(), client -> {
            client.sendMessage(MISSING_SCOPES_MESSAGE);
            client.close(ClosureCode.NORMAL, "Not allowed!");
        });
    }

}
