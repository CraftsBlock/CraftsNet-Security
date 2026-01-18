package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.RouteRegistry;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.requirements.web.WebRequirement;
import de.craftsblock.craftsnet.api.requirements.websocket.WebSocketRequirement;
import de.craftsblock.craftsnet.api.utils.Context;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import org.jetbrains.annotations.ApiStatus;

import java.lang.annotation.Annotation;
import java.util.Collections;
import java.util.List;

@ApiStatus.Internal
public sealed interface ScopeRequirement
        permits ScopeRequirement.Http, ScopeRequirement.WebSocket {

    default boolean handleRequire(Context context, RouteRegistry.EndpointMapping mapping) {
        if (!context.containsKey(Token.class)) {
            return true;
        }

        if (!mapping.isPresent(getAnnotation(), "value")) {
            Token token = context.getTyped(Token.class);
            List<String> scopes = mapping.getRequirements(getAnnotation(), "value");
            context.put(new ScopeResult(scopes, token.scopes().containsAll(scopes)));
        } else {
            context.put(new ScopeResult(Collections.emptyList(), true));
        }

        return true;
    }

    Class<? extends Annotation> getAnnotation();

    @ApiStatus.Internal
    @AutoRegister(startup = Startup.LOAD)
    final class Http extends WebRequirement implements ScopeRequirement {

        public Http() {
            super(RequireScope.class);
        }

        @Override
        public boolean applies(Request request, RouteRegistry.EndpointMapping mapping) {
            return handleRequire(request.getExchange().context(), mapping);
        }

    }

    @ApiStatus.Internal
    @AutoRegister(startup = Startup.LOAD)
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements ScopeRequirement {

        public WebSocket() {
            super(RequireScope.class);
        }

        @Override
        public boolean applies(WebSocketClient webSocketClient, RouteRegistry.EndpointMapping mapping) {
            return handleRequire(webSocketClient.getContext(), mapping);
        }

    }

}
