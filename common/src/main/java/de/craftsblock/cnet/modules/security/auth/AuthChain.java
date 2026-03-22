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

public class AuthChain {

    private final EnumMap<Scheme, Queue<AuthAdapter>> adapters = new EnumMap<>(Scheme.class);

    private final Exclusions exclusions = new Exclusions();

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

    public AuthResult authenticate(BaseExchange exchange) {
        if (exchange instanceof Exchange http) {
            return authenticateHttp(http);
        } else if (exchange instanceof SocketExchange webSocket) {
            return authenticateWebSocket(webSocket);
        }

        throw new IllegalStateException("Unexpected exchange: " + exchange.getClass().getName());
    }

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

    private Queue<AuthAdapter> computeAuthAdapterQueue(Scheme scheme) {
        synchronized (adapters) {
            return adapters.computeIfAbsent(scheme, s -> new LinkedBlockingQueue<>());
        }
    }

    public Exclusions getExclusions() {
        return exclusions;
    }

    public static @NotNull AuthChain getInstance() {
        return CraftsNetSecurity.getAuthChain();
    }

}
