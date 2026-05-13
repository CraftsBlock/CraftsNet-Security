package de.craftsblock.cnet.modules.security.auth.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.autoregister.meta.constructors.FallbackConstructor;
import de.craftsblock.craftsnet.autoregister.meta.constructors.PreferConstructor;
import de.craftsblock.craftsnet.events.sockets.ClientConnectEvent;

/**
 * Listener responsible for authenticating incoming websocket
 * connection attempts before the connection is fully established.
 * <p>
 * This listener is triggered during the {@link ClientConnectEvent}
 * and executes the global authentication chain for the connecting
 * websocket client.
 * <p>
 * If authentication fails, the connection is rejected and a JSON
 * error message is sent to the client before disconnecting.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AuthListener
 * @since 1.0.0
 */
@AutoRegister(startup = Startup.LOAD)
public record WebSocketConnectListener(CraftsNet craftsNet, CraftsNetSecurity addon) implements ListenerAdapter, AuthListener<WebSocketClient> {

    /**
     * Preferred constructor used by the auto registration system.
     *
     * @param craftsNet The active CraftsNet instance.
     * @param addon     The active security addon instance.
     */
    @PreferConstructor
    public WebSocketConnectListener {
    }

    /**
     * Fallback constructor that resolves the active
     * {@link CraftsNetSecurity} instance automatically.
     *
     * @param craftsNet The active CraftsNet instance.
     */
    @FallbackConstructor
    public WebSocketConnectListener(CraftsNet craftsNet) {
        this(craftsNet, CraftsNetSecurity.getInstance());
    }

    /**
     * Handles incoming websocket client connection attempts
     * and executes authentication validation.
     * <p>
     * If authentication fails, the connection is rejected and
     * an error message is sent to the client.
     *
     * @param event The client connect event.
     */
    @EventHandler(priority = EventPriority.LOW, ignoreWhenCancelled = true)
    public void handleConnect(ClientConnectEvent event) {
        final SocketExchange exchange = event.getExchange();
        this.authenticate(
                exchange, event, exchange.client(),
                (client, result) -> client.sendMessage(
                        Json.empty()
                                .set("success", false)
                                .set("error.code", result.getCode())
                                .set("error.message", result.getReason())
                )
        );
    }

}
