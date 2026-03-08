package de.craftsblock.cnet.modules.security.token.adapter;

import com.google.gson.JsonSyntaxException;
import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.adapter.AuthAdapter;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.event.TokenUsedEvent;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.Opcode;
import de.craftsblock.craftsnet.api.websocket.SocketExchange;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.events.sockets.message.IncomingSocketMessageEvent;
import de.craftsblock.craftsnet.events.sockets.message.OutgoingSocketMessageEvent;

public class WebSocketTokenAuthAdapter implements ListenerAdapter, AuthAdapter.WebSocket {

    private static final String MESSAGE_LITERAL_WRONG_AUTH = "Not allowed!";
    private static final Json MESSAGE_WRONG_AUTH = Json.empty()
            .set("success", false)
            .set("error.code", 400)
            .set("error.message", MESSAGE_LITERAL_WRONG_AUTH);

    @Override
    public AuthResult authenticate(SocketExchange exchange) {
        exchange.context().put(new RequireAuth());
        return AuthResult.skip();
    }

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

            Token token = CraftsNetSecurity.getTokenManager().getValidatedToken(json.getString("token"));
            if (token == null) {
                failAuth(client, "WRONG TOKEN");
                return;
            }

            CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenUsedEvent(token));
            context.put(token);
            context.remove(RequireAuth.class);
        } catch (JsonSyntaxException ignored) {
            failAuth(client, "NOT A JSON");
        }
    }

    private void failAuth(WebSocketClient client, String reason) {
        client.sendMessage(MESSAGE_WRONG_AUTH);
        CraftsNetSecurity.getInstance().getLogger().debug("%s failed to authenticate \u001b[38;5;9m[%s]", client.getIp(), reason);
        client.close(ClosureCode.NORMAL, MESSAGE_LITERAL_WRONG_AUTH);
    }

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

    private static class RequireAuth {
    }

}
