package de.craftsblock.cnet.modules.security.token.listener;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.adapter.WebSocketTokenAuthAdapter;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.event.cache.RevalidateCacheEvent;
import de.craftsblock.cnet.modules.security.token.event.cache.RevalidateTokenCacheEvent;
import de.craftsblock.cnet.modules.security.token.group.UsedGroups;
import de.craftsblock.cnet.modules.security.token.scope.UsedScopes;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.http.status.HttpStatus;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.ClosureCode;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;

@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class WebSocketRevalidateCacheListener implements ListenerAdapter {

    private static final String MESSAGE_NO_LONGER_AUTHENTICATED = Json.empty()
            .set("success", false)
            .set("error.code", HttpStatus.ClientError.UNAUTHORIZED.getCode())
            .set("error.message", "No longer authenticated!")
            .toString();

    @EventHandler
    public void handleCacheRevalidation(RevalidateCacheEvent<?> event) {
        if (event instanceof RevalidateTokenCacheEvent && event.hasSubject()) {
            Collection<WebSocketClient> clients = WebSocketTokenAuthAdapter.getAuthenticatedClients()
                    .get(event.getSubject());

            if (clients == null || clients.isEmpty()) {
                return;
            }

            clients.forEach(this::revalidateWebSocketClient);
            return;
        }

        for (Collection<WebSocketClient> clients : WebSocketTokenAuthAdapter.getAuthenticatedClients().values()) {
            clients.forEach(this::revalidateWebSocketClient);
        }
    }

    private void revalidateWebSocketClient(WebSocketClient client) {
        final Context context = client.getContext();
        final Token token = context.getTyped(Token.class);
        final UsedScopes usedScopes = context.getTyped(UsedScopes.class);
        final UsedGroups usedGroups = context.getTyped(UsedGroups.class);
        if (token == null || usedScopes == null || usedGroups == null) {
            clientNoLongerAuthenticated(client);
            return;
        }

        StoreDriver storeDriver = StoreDriver.getInstance();
        Token freshToken = storeDriver.loadToken(token.id());
        if (token.equals(freshToken)) {
            context.put(freshToken);
            return;
        }

        if (freshToken != null
                && freshToken.scopes().containsAll(usedScopes.scopes())
                && freshToken.groupNames().containsAll(usedGroups.groups())) {
            context.put(freshToken);
            return;
        }

        clientNoLongerAuthenticated(client);
    }

    private void clientNoLongerAuthenticated(@NotNull WebSocketClient client) {
        final Context context = client.getContext();
        context.remove(Token.class);
        context.remove(UsedGroups.class);
        context.remove(UsedScopes.class);

        client.sendMessage(MESSAGE_NO_LONGER_AUTHENTICATED);
        client.close(ClosureCode.SERVER_ERROR, "No longer authenticated");
    }

}
