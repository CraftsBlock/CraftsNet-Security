package de.craftsblock.cnet.modules.security.token.group;

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
 * Middleware responsible for resolving and validating group-based access
 * requirements during request and websocket processing.
 * <p>
 * This middleware evaluates {@link UsedGroups} entries stored in the
 * exchange context and verifies them against the groups available on the
 * authenticated {@link Token}. If the token does not satisfy the required
 * groups, the request or websocket interaction is cancelled.
 * <p>
 * On successful validation, the resolved groups are transferred into a
 * {@link UsedGroups} context entry for downstream processing.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class GroupResolveMiddleware implements ListenerAdapter {

    private static final Json MISSING_GROUPS_MESSAGE = Json.empty()
            .set("success", false)
            .set("error.code", 400)
            .set("error.message", "Not allowed!");

    /**
     * Handles group validation for both HTTP and WebSocket exchanges.
     * <p>
     * This method extract the {@link UsedGroups} from the endpoints
     * and then passes it with the context to
     * {@link #handle(Context, UsedGroups, CancellableEvent, Object, Consumer)}
     *
     * @param exchange  The active exchange (HTTP or WebSocket)
     * @param mappings  The endpoint mappings used.
     * @param event     The cancellable event associated with the exchange
     * @param subject   The subject that should receive failure handling (response or client)
     * @param onFailure Callback executed when group validation fails
     * @param <T>       The type of the subject (response or websocket client)
     */
    private <T> void handle(BaseExchange exchange, Collection<RouteRegistry.EndpointMapping> mappings,
                            CancellableEvent event, T subject, Consumer<T> onFailure) {
        final Context context = exchange.context();
        final UsedGroups request = UsedGroups.fromMappings(mappings);
        if (request.groups().isEmpty()) {
            return;
        }

        handle(context, request, event, subject, onFailure);
    }

    /**
     * Handles group validation for contexts.
     * <p>
     * This method ensures that a valid {@link Token} exists in the context
     * and that all required groups defined in {@link UsedGroups} are satisfied.
     * If validation fails, the provided cancellation consumer is executed.
     *
     * @param context    The context which should hold the {@link Token}.
     * @param usedGroups The groups that must be present on the token.
     * @param event      The cancellable event associated with the exchange
     * @param subject    The subject that should receive failure handling (response or client)
     * @param onFailure  Callback executed when group validation fails
     * @param <T>        The type of the subject (response or websocket client)
     */
    private <T> void handle(Context context, UsedGroups usedGroups,
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
        if (token.groupNames().containsAll(usedGroups.groups())) {
            return;
        }

        event.setCancelled(true);
        if (event instanceof EventWithCancelReason withCancelReason) {
            withCancelReason.setCancelReason("GROUP MISMATCH");
        }

        onFailure.accept(subject);
    }

    /**
     * Validates group requirements during HTTP route request processing.
     *
     * @param event The route request event being processed
     */
    @EventHandler(priority = EventPriority.NORMAL, ignoreWhenCancelled = true)
    public void handleRequest(RouteRequestEvent event) {
        final Exchange exchange = event.getExchange();
        handle(exchange, event.getMappings(), event, exchange.response(), response -> {
            if (!response.headersSent()) {
                response.setStatus(HttpStatus.ClientError.BAD_REQUEST);
            }

            if (!response.sendingFile()) {
                response.print(MISSING_GROUPS_MESSAGE);
            }
        });
    }

    /**
     * Handles the connection of websocket clients.
     * <p>
     * Ensures that each context holds the {@link UsedGroups} as defined
     * in their {@link de.craftsblock.craftsnet.api.RouteRegistry.EndpointMapping}.
     *
     * @param event The {@link ClientConnectEvent} that has been fired.
     */
    @EventHandler(priority = EventPriority.LOW, ignoreWhenCancelled = true)
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
        final UsedGroups usedGroups = UsedGroups.fromMappings(mappings);
        context.put(usedGroups);
    }

    /**
     * Validates group requirements during incoming WebSocket message processing.
     *
     * @param event The incoming websocket message event
     */
    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleWebSocketMessage(IncomingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        final WebSocketClient client = exchange.client();
        final Context context = client.getContext();

        final UsedGroups usedGroups = context.getTyped(UsedGroups.class);
        if (usedGroups == null) {
            GroupResolveMiddleware.disconnectNotAllowed(client);
            return;
        }

        handle(context, usedGroups, event, exchange.client(), GroupResolveMiddleware::disconnectNotAllowed);
    }

    /**
     * Disconnects a client using the {@link #MISSING_GROUPS_MESSAGE}
     * message and a {@link ClosureCode#NORMAL} close code.
     *
     * @param client The client to disconnect.
     */
    private static void disconnectNotAllowed(WebSocketClient client) {
        client.sendMessage(MISSING_GROUPS_MESSAGE);
        client.close(ClosureCode.NORMAL, "Not allowed!");
    }

}
