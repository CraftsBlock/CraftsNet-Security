package de.craftsblock.cnet.modules.security.token.adapter;

import com.google.gson.JsonSyntaxException;
import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.adapter.AuthAdapter;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.TokenManager;
import de.craftsblock.cnet.modules.security.token.event.TokenUsedEvent;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.http.status.HttpStatus;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.Opcode;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.autoregister.meta.Instantiate;
import de.craftsblock.craftsnet.events.sockets.ClientDisconnectEvent;
import de.craftsblock.craftsnet.events.sockets.message.IncomingSocketMessageEvent;
import de.craftsblock.craftsnet.events.sockets.message.OutgoingSocketMessageEvent;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import org.jetbrains.annotations.UnmodifiableView;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * WebSocket authentication adapter that enforces token-based authentication
 * for incoming socket connections.
 * <p>
 * This adapter acts as a gatekeeper for WebSocket communication. Clients are
 * initially marked as requiring authentication and must provide a valid token
 * via an incoming JSON message before being granted full access.
 * <p>
 * Authenticated clients are tracked per token ID, and lifecycle events are
 * used to manage connection state and cleanup on disconnect.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD, instantiate = Instantiate.NEW)
public class WebSocketTokenAuthAdapter implements ListenerAdapter, AuthAdapter.WebSocket {

    private static final @NotNull String MESSAGE_LITERAL_WRONG_AUTH = "Not allowed!";
    private static final @NotNull Json MESSAGE_WRONG_AUTH = Json.empty()
            .set("success", false)
            .set("error.code", HttpStatus.ClientError.BAD_REQUEST.getCode())
            .set("error.message", MESSAGE_LITERAL_WRONG_AUTH);

    private static final @NotNull Map<Long, Collection<WebSocketClient>> AUTHENTICATED_CLIENTS = new ConcurrentHashMap<>();
    private static final @UnmodifiableView
    @NotNull Map<Long, Collection<WebSocketClient>> AUTHENTICATED_CLIENTS_VIEW = Collections.unmodifiableMap(AUTHENTICATED_CLIENTS);

    /**
     * Marks a new WebSocket connection as requiring authentication.
     * <p>
     * The actual authentication is deferred to incoming message handling.
     *
     * @param exchange The socket exchange being authenticated.
     * @return Always returns {@link AuthResult#skip()} since authentication
     * is handled asynchronously via messages.
     */
    @Override
    public AuthResult authenticate(SocketExchange exchange) {
        exchange.context().put(new RequireAuth());
        return AuthResult.skip();
    }

    /**
     * Handles client disconnect events and removes the client from the
     * authenticated registry if necessary.
     *
     * @param event The disconnect event.
     */
    @EventHandler(priority = EventPriority.NORMAL)
    public void handleDisconnect(ClientDisconnectEvent event) {
        final WebSocketClient client = event.getClient();
        final Context context = client.getContext();
        final Token token = context.getTyped(Token.class);
        if (token == null) {
            return;
        }

        synchronized (AUTHENTICATED_CLIENTS) {
            Collection<WebSocketClient> clients = AUTHENTICATED_CLIENTS.get(token.id());
            if (clients == null) {
                return;
            }

            clients.remove(client);
            if (clients.isEmpty()) {
                AUTHENTICATED_CLIENTS.remove(token.id(), clients);
            }
        }
    }

    /**
     * Intercepts incoming WebSocket messages and performs authentication
     * if required.
     * <p>
     * This method expects the first message to contain a JSON payload with
     * a valid token. Once authenticated, the client is marked as authorized
     * and allowed to continue communication.
     *
     * @param event The incoming message event.
     */
    @EventHandler(priority = EventPriority.NORMAL, ignoreWhenCancelled = true)
    public void handleIncomingMessage(IncomingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        final Context context = exchange.context();
        if (!context.containsKey(RequireAuth.class)) {
            return;
        }

        final WebSocketClient client = event.getClient();
        event.setCancelled(true);
        if (!event.getOpcode().equals(Opcode.TEXT)) {
            failAuth(client, "NOT TEXT");
            return;
        }

        try {
            String message = event.getUtf8();
            Json json = JsonParser.parse(message);
            if (!json.contains("token")) {
                failAuth(client, "NO TOKEN");
                return;
            }

            Token token = TokenManager.getInstance().getValidated(json.getString("token"));
            if (token == null) {
                failAuth(client, "WRONG TOKEN");
                return;
            }

            CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenUsedEvent(token));
            context.put(token);
            context.put(new Authenticated(System.currentTimeMillis()));
            context.remove(RequireAuth.class);

            synchronized (AUTHENTICATED_CLIENTS) {
                AUTHENTICATED_CLIENTS.computeIfAbsent(token.id(), id -> new ConcurrentLinkedQueue<>())
                        .add(client);
            }
        } catch (JsonSyntaxException ignored) {
            failAuth(client, "NOT A JSON");
        }
    }

    /**
     * Handles authentication failure by sending an error response
     * and closing the connection.
     *
     * @param client The client to reject.
     * @param reason The reason for failure.
     */
    private void failAuth(WebSocketClient client, String reason) {
        client.sendMessage(MESSAGE_WRONG_AUTH);
        CraftsNetSecurity.getInstance().getLogger().debug("%s failed to authenticate \u001b[38;5;9m[%s]", client.getIp(), reason);
        client.close(ClosureCode.NORMAL, MESSAGE_LITERAL_WRONG_AUTH);
    }

    /**
     * Prevents unauthenticated outgoing messages from being sent
     * through the WebSocket connection.
     *
     * @param event The outgoing message event.
     */
    @EventHandler(ignoreWhenCancelled = true)
    public void handleOutgoingMessage(OutgoingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        if (!exchange.context().containsKey(RequireAuth.class)) {
            return;
        }

        if (event.getOpcode().equals(Opcode.TEXT) && event.getUtf8().equals(MESSAGE_WRONG_AUTH.toString())) {
            return;
        }

        event.setCancelled(true);
    }

    /**
     * Checks whether a WebSocket client has successfully authenticated.
     *
     * @param client The client to check.
     * @return {@code true} if authenticated, otherwise {@code false}.
     */
    public static boolean isAuthenticated(@NotNull WebSocketClient client) {
        return client.getContext().containsKey(Authenticated.class);
    }

    /**
     * Returns the timestamp at which the client authenticated.
     *
     * @param client The client to inspect.
     * @return The authentication timestamp, {@code -1} if still pending,
     * or {@code -2} if no authentication data exists.
     */
    public static @Range(from = -2, to = Long.MAX_VALUE) long getAuthenticationTimestamp(@NotNull WebSocketClient client) {
        final Context context = client.getContext();
        if (context.containsKey(RequireAuth.class)) {
            return -1;
        }

        final Authenticated authenticated = client.getContext().getTyped(Authenticated.class);
        if (authenticated == null) {
            return -2;
        }

        return authenticated.timestamp();
    }

    /**
     * Returns an immutable view of all authenticated clients grouped by token ID.
     *
     * @return Map of token IDs to their associated authenticated clients.
     */
    public static @UnmodifiableView @NotNull Map<Long, Collection<WebSocketClient>> getAuthenticatedClients() {
        return AUTHENTICATED_CLIENTS_VIEW;
    }

    /**
     * Marker object indicating that a client still requires authentication.
     */
    private static class RequireAuth {
    }

    /**
     * Internal record storing authentication timestamp metadata.
     */
    private record Authenticated(long timestamp) {
    }

}
