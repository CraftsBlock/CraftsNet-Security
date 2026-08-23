package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftscore.event.CancellableEvent;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.BaseExchange;
import de.craftsblock.craftsnet.api.RouteRegistry;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.status.HttpStatus;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.EventWithCancelReason;
import de.craftsblock.craftsnet.events.requests.routes.RouteRequestEvent;
import de.craftsblock.craftsnet.events.sockets.ClientConnectEvent;
import de.craftsblock.craftsnet.events.sockets.message.IncomingSocketMessageEvent;
import org.jetbrains.annotations.ApiStatus;

import java.util.Collection;
import java.util.function.Consumer;

/**
 * Middleware responsible for resolving and validating required scopes.
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

    private static final Json MISSING_SCOPES_MESSAGE = Json.empty()
            .set("success", false)
            .set("error.code", HttpStatus.ClientError.BAD_REQUEST.getCode())
            .set("error.message", "Not allowed!");

    /**
     * Handles scope validation for both HTTP and WebSocket exchanges.
     * <p>
     * This method extract the {@link UsedScopes} from the endpoints
     * and then passes it with the context to
     * {@link #handle(Context, UsedScopes, CancellableEvent, Object, Consumer)}
     *
     * @param exchange  The active exchange (HTTP or WebSocket)
     * @param mappings  The endpoint mappings used.
     * @param event     The cancellable event associated with the exchange
     * @param subject   The subject that should receive failure handling (response or client)
     * @param onFailure Callback executed when scope validation fails
     * @param <T>       The type of the subject (response or websocket client)
     */
    private <T> void handle(BaseExchange exchange, Collection<RouteRegistry.EndpointMapping> mappings,
                            CancellableEvent event, T subject, Consumer<T> onFailure) {
        final Context context = exchange.context();
        final UsedScopes request = UsedScopes.fromMappings(mappings);
        if (request.scopes().isEmpty()) {
            return;
        }

        handle(context, request, event, subject, onFailure);
    }

    /**
     * Handles scope validation for contexts.
     * <p>
     * This method ensures that a valid {@link Token} exists in the context
     * and that all required scops defined in {@link UsedScopes} are satisfied.
     * If validation fails, the provided cancellation consumer is executed.
     *
     * @param context    The context which should hold the {@link Token}.
     * @param usedScopes The scops that must be present on the token.
     * @param event      The cancellable event associated with the exchange
     * @param subject    The subject that should receive failure handling (response or client)
     * @param onFailure  Callback executed when scope validation fails
     * @param <T>        The type of the subject (response or websocket client)
     */
    private <T> void handle(Context context, UsedScopes usedScopes,
                            CancellableEvent event, T subject, Consumer<T> onFailure) {
        if (!context.containsKey(Token.class)) {
            event.setCancelled(true);
            if (event instanceof EventWithCancelReason withCancelReason) {
                withCancelReason.setCancelReason("NO TOKEN");
            }

            onFailure.accept(subject);
            return;
        }

        final Token token = context.getTyped(Token.class);
        if (token.scopes().containsAll(usedScopes.scopes())) {
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
        handle(exchange, event.getMappings(), event, exchange.response(), response -> {
            if (!response.headersSent()) {
                response.setStatus(HttpStatus.ClientError.BAD_REQUEST);
            }

            if (!response.sendingFile()) {
                response.print(MISSING_SCOPES_MESSAGE);
            }
        });
    }

    /**
     * Handles the connection of websocket clients.
     * <p>
     * Ensures that each context holds the {@link UsedScopes} as defined
     * in their {@link de.craftsblock.craftsnet.api.RouteRegistry.EndpointMapping}.
     *
     * @param event The {@link ClientConnectEvent} that has been fired.
     */
    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleWebSocketConnect(ClientConnectEvent event) {
        final SocketExchange exchange = event.getExchange();
        final WebSocketClient client = exchange.client();
        final var endpoints = client.getEndpoint();

        if (endpoints == null) {
            return;
        }

        final Collection<RouteRegistry.EndpointMapping> mappings = endpoints.values().stream()
                .flatMap(Collection::stream)
                .toList();

        final Context context = client.getContext();
        final UsedScopes usedScopes = UsedScopes.fromMappings(mappings);
        context.put(usedScopes);
    }

    /**
     * Handles incoming WebSocket messages and applies scope validation logic.
     *
     * @param event The incoming socket message event
     */
    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleWebSocketMessage(IncomingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        final WebSocketClient client = exchange.client();
        final Context context = client.getContext();

        final UsedScopes usedScopes = context.getTyped(UsedScopes.class);
        if (usedScopes == null) {
            ScopeResolveMiddleware.disconnectNotAllowed(client);
            return;
        }

        handle(context, usedScopes, event, exchange.client(), ScopeResolveMiddleware::disconnectNotAllowed);
    }

    /**
     * Disconnects a client using the {@link #MISSING_SCOPES_MESSAGE}
     * message and a {@link ClosureCode#NORMAL} close code.
     *
     * @param client The client to disconnect.
     */
    private static void disconnectNotAllowed(WebSocketClient client) {
        client.sendMessage(MISSING_SCOPES_MESSAGE);
        client.close(ClosureCode.NORMAL, "Not allowed!");
    }

}
