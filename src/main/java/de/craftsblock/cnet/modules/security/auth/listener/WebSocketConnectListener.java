package de.craftsblock.cnet.modules.security.auth.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftscore.buffer.BufferUtil;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.autoregister.meta.constructors.FallbackConstructor;
import de.craftsblock.craftsnet.autoregister.meta.constructors.PreferConstructor;
import de.craftsblock.craftsnet.events.sockets.ClientConnectEvent;

@AutoRegister(startup = Startup.LOAD)
public record WebSocketConnectListener(CraftsNet craftsNet, CraftsNetSecurity addon) implements ListenerAdapter, AuthListener<WebSocketClient> {

    @PreferConstructor
    public WebSocketConnectListener {
    }

    @FallbackConstructor
    public WebSocketConnectListener(CraftsNet craftsNet) {
        this(craftsNet, CraftsNetSecurity.getInstance());
    }

    @EventHandler(priority = EventPriority.NORMAL, ignoreWhenCancelled = true)
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
