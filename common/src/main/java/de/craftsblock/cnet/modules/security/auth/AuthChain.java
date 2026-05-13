package de.craftsblock.cnet.modules.security.auth;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.adapter.AuthAdapter;
import de.craftsblock.cnet.modules.security.auth.exclusion.Exclusions;
import de.craftsblock.craftsnet.api.BaseExchange;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.utils.Scheme;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Represents the central authentication chain registry and execution
 * pipeline used by the security module.
 * <p>
 * {@link AuthAdapter Auth adapters} are grouped by their supported
 * {@link Scheme} and executed sequentially whenever an incoming
 * request or websocket connection is authenticated.
 * <p>
 * Adapters may either approve or reject a request. As soon as an
 * adapter returns a failed {@link AuthResult}, the authentication
 * process is immediately aborted and the failure result is returned.
 * <p>
 * The authentication chain also supports exclusions through
 * {@link Exclusions}, allowing specific routes or websocket paths
 * to bypass authentication entirely.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthAdapter
 * @see AuthResult
 * @see Exclusions
 * @since 1.0.0
 */
public class AuthChain {

    private final EnumMap<Scheme, Queue<AuthAdapter>> adapters = new EnumMap<>(Scheme.class);

    private final Exclusions exclusions = new Exclusions();

    /**
     * Registers the given authentication adapter within all
     * applicable authentication adapter queues.
     * <p>
     * Depending on the implemented adapter interfaces, the adapter
     * may be registered for HTTP authentication, websocket
     * authentication, or both.
     *
     * @param adapter The adapter to register.
     */
    public void append(AuthAdapter adapter) {
        computeApplicableAuthAdapterQueues(adapter).forEach(authAdapters -> {
            synchronized (authAdapters) {
                if (authAdapters.contains(adapter)) {
                    return;
                }

                authAdapters.offer(adapter);
            }
        });
    }

    /**
     * Removes the given authentication adapter from all
     * applicable authentication adapter queues.
     *
     * @param adapter The adapter to remove.
     */
    public void remove(AuthAdapter adapter) {
        computeApplicableAuthAdapterQueues(adapter).forEach(authAdapters -> {
            synchronized (authAdapters) {
                if (!authAdapters.contains(adapter)) {
                    return;
                }

                authAdapters.remove(adapter);
            }
        });
    }

    /**
     * Checks whether the given HTTP authentication adapter
     * is currently registered.
     *
     * @param http The HTTP authentication adapter to check.
     * @return {@code true} if the adapter is registered,
     * otherwise {@code false}.
     */
    public boolean isHttpAdapterRegistered(AuthAdapter.Http http) {
        if (!adapters.containsKey(Scheme.HTTP)) {
            return false;
        }

        return adapters.get(Scheme.HTTP).contains(http);
    }

    /**
     * Checks whether the given websocket authentication adapter
     * is currently registered.
     *
     * @param webSocket The websocket authentication adapter to check.
     * @return {@code true} if the adapter is registered,
     * otherwise {@code false}.
     */
    public boolean isWebSocketAdapterRegistered(AuthAdapter.WebSocket webSocket) {
        if (!adapters.containsKey(Scheme.WS)) {
            return false;
        }

        return adapters.get(Scheme.WS).contains(webSocket);
    }

    /**
     * Authenticates the given exchange using the appropriate
     * authentication adapter chain.
     * <p>
     * The authentication type is automatically determined based
     * on the concrete exchange implementation.
     *
     * @param exchange The exchange to authenticate.
     * @return The resulting {@link AuthResult}.
     * @throws IllegalStateException If the exchange type is unsupported.
     */
    public AuthResult authenticate(BaseExchange exchange) {
        if (exchange instanceof Exchange http) {
            return authenticateHttp(http);
        } else if (exchange instanceof SocketExchange webSocket) {
            return authenticateWebSocket(webSocket);
        }

        throw new IllegalStateException("Unexpected exchange: " + exchange.getClass().getName());
    }

    /**
     * Executes the HTTP authentication chain for the given exchange.
     * <p>
     * If the request is excluded from authentication, the method
     * immediately returns {@link AuthResult#skip()}.
     *
     * @param exchange The HTTP exchange to authenticate.
     * @return The resulting {@link AuthResult}.
     * @throws IllegalStateException If a non HTTP adapter is found
     *                               within the HTTP adapter queue.
     */
    private AuthResult authenticateHttp(Exchange exchange) {
        final Request request = exchange.request();
        if (this.exclusions.isHttpExcluded(request.getUrl(), request.getHttpMethod())) {
            return AuthResult.skip();
        }

        Queue<AuthAdapter> httpAdapters = this.computeAuthAdapterQueue(Scheme.HTTP);
        synchronized (httpAdapters) {
            for (AuthAdapter adapter : httpAdapters) {
                if (!(adapter instanceof AuthAdapter.Http httpAuthAdapter)) {
                    throw new IllegalStateException("Found a non http auth adapter "
                            + adapter.getClass().getName() + " in the http adapter list!");
                }

                AuthResult result = httpAuthAdapter.authenticate(exchange);
                if (result.isFailure()) {
                    return result;
                }
            }
        }

        return AuthResult.ok();
    }

    /**
     * Executes the websocket authentication chain for the given exchange.
     * <p>
     * If the websocket path is excluded from authentication,
     * the method immediately returns {@link AuthResult#skip()}.
     *
     * @param exchange The websocket exchange to authenticate.
     * @return The resulting {@link AuthResult}.
     * @throws IllegalStateException If a non websocket adapter is found
     *                               within the websocket adapter queue.
     */
    private AuthResult authenticateWebSocket(SocketExchange exchange) {
        final WebSocketClient client = exchange.client();
        if (this.exclusions.isWebSocketExcluded(client.getPath())) {
            return AuthResult.skip();
        }

        Queue<AuthAdapter> webSocketAdapters = this.computeAuthAdapterQueue(Scheme.WS);
        synchronized (webSocketAdapters) {
            for (AuthAdapter adapter : webSocketAdapters) {
                if (!(adapter instanceof AuthAdapter.WebSocket webSocketAuthAdapter)) {
                    throw new IllegalStateException("Found a non web socket auth adapter "
                            + adapter.getClass().getName() + " in the web socket adapter list!");
                }

                AuthResult result = webSocketAuthAdapter.authenticate(exchange);
                if (result.isFailure()) {
                    return result;
                }
            }
        }

        return AuthResult.ok();
    }

    /**
     * Computes all authentication adapter queues that are applicable
     * for the given adapter.
     * <p>
     * An adapter may support multiple schemes and therefore be added
     * to multiple authentication queues.
     *
     * @param adapter The adapter whose target queues should be resolved.
     * @return A collection containing all applicable adapter queues.
     */
    private Collection<Queue<AuthAdapter>> computeApplicableAuthAdapterQueues(AuthAdapter adapter) {
        Collection<Queue<AuthAdapter>> authAdapters = new ArrayList<>();

        if (adapter instanceof AuthAdapter.Http) {
            authAdapters.add((computeAuthAdapterQueue(Scheme.HTTP)));
        }

        if (adapter instanceof AuthAdapter.WebSocket) {
            authAdapters.add(computeAuthAdapterQueue(Scheme.WS));
        }

        return authAdapters;
    }

    /**
     * Retrieves or creates the authentication adapter queue
     * for the given scheme.
     *
     * @param scheme The scheme whose adapter queue should be retrieved.
     * @return The authentication adapter queue for the scheme.
     */
    private Queue<AuthAdapter> computeAuthAdapterQueue(Scheme scheme) {
        synchronized (adapters) {
            return adapters.computeIfAbsent(scheme, s -> new LinkedBlockingQueue<>());
        }
    }

    /**
     * Retrieves the authentication exclusion registry.
     *
     * @return The configured {@link Exclusions} instance.
     */
    public Exclusions getExclusions() {
        return exclusions;
    }

    /**
     * Retrieves the global authentication chain instance.
     *
     * @return The active {@link AuthChain} instance.
     */
    public static @NotNull AuthChain getInstance() {
        return CraftsNetSecurity.getAuthChain();
    }

}
