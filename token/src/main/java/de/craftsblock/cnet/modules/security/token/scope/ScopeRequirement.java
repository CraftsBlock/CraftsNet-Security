package de.craftsblock.cnet.modules.security.token.scope;

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

    default boolean injectRequest(Context context, RouteRegistry.EndpointMapping mapping) {
        if (mapping.isPresent(getAnnotation(), "value")) {
            List<String> scopes = mapping.getRequirements(getAnnotation(), "value");
            context.put(new ScopeRequest(scopes));
        } else {
            context.put(new ScopeRequest(Collections.emptyList()));
        }

        return true;
    }

    Class<? extends Annotation> getAnnotation();

    @AutoRegister(startup = Startup.LOAD)
    final class Http extends WebRequirement implements ScopeRequirement {

        public Http() {
            super(RequireScope.class);
        }

        @Override
        public boolean applies(Request request, RouteRegistry.EndpointMapping mapping) {
            return injectRequest(request.getExchange().context(), mapping);
        }

    }

    @AutoRegister(startup = Startup.LOAD)
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements ScopeRequirement {

        public WebSocket() {
            super(RequireScope.class);
        }

        @Override
        public boolean applies(WebSocketClient webSocketClient, RouteRegistry.EndpointMapping mapping) {
            return injectRequest(webSocketClient.getContext(), mapping);
        }

    }

}
