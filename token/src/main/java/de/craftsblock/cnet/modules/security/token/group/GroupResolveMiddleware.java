package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.group.GroupRequest;
import de.craftsblock.cnet.modules.security.token.group.UsedGroups;
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

@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class GroupResolveMiddleware implements ListenerAdapter {

    private final Json MISSING_GROUPS_MESSAGE = Json.empty()
            .set("success", false)
            .set("error.code", 400)
            .set("error.message", "Not allowed!");

    private <T> void handle(BaseExchange exchange, CancellableEvent event, T subject, Consumer<T> onFailure) {
        Context context = exchange.context();
        if (context == null || !context.containsKey(GroupRequest.class)) {
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
        final GroupRequest result = context.getTyped(GroupRequest.class);
        if (token.groupNames().containsAll(result.groups())) {
            context.remove(GroupRequest.class);
            context.put(new UsedGroups(Collections.unmodifiableList(result.groups())));
            return;
        }

        event.setCancelled(true);
        if (event instanceof EventWithCancelReason withCancelReason) {
            withCancelReason.setCancelReason("GROUP MISMATCH");
        }

        onFailure.accept(subject);
    }

    @EventHandler(priority = EventPriority.NORMAL, ignoreWhenCancelled = true)
    public void handleRequest(RouteRequestEvent event) {
        final Exchange exchange = event.getExchange();
        handle(exchange, event, exchange.response(), response -> {
            if (!response.headersSent()) {
                response.setStatus(HttpStatus.ClientError.BAD_REQUEST);
            }

            if (!response.sendingFile()) {
                response.print(MISSING_GROUPS_MESSAGE);
            }
        });
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreWhenCancelled = true)
    public void handleWebSocketMessage(IncomingSocketMessageEvent event) {
        final SocketExchange exchange = event.getExchange();
        handle(exchange, event, exchange.client(), client -> {
            client.sendMessage(MISSING_GROUPS_MESSAGE);
            client.close(ClosureCode.NORMAL, "Not allowed!");
        });
    }

}
