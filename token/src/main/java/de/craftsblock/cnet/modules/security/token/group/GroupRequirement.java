package de.craftsblock.cnet.modules.security.token.group;

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
public sealed interface GroupRequirement
        permits GroupRequirement.Http, GroupRequirement.WebSocket {

    default boolean injectRequest(Context context, RouteRegistry.EndpointMapping mapping) {
        if (mapping.isPresent(getAnnotation(), "value")) {
            List<String> groups = mapping.getRequirements(getAnnotation(), "value");
            context.put(new GroupRequest(groups));
        } else {
            context.put(new GroupRequest(Collections.emptyList()));
        }

        return true;
    }

    Class<? extends Annotation> getAnnotation();

    @AutoRegister(startup = Startup.LOAD)
    final class Http extends WebRequirement implements GroupRequirement {

        public Http() {
            super(RequireGroup.class);
        }

        @Override
        public boolean applies(Request request, RouteRegistry.EndpointMapping mapping) {
            return injectRequest(request.getExchange().context(), mapping);
        }

    }

    @AutoRegister(startup = Startup.LOAD)
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements GroupRequirement {

        public WebSocket() {
            super(RequireGroup.class);
        }

        @Override
        public boolean applies(WebSocketClient client, RouteRegistry.EndpointMapping mapping) {
            return injectRequest(client.getContext(), mapping);
        }
    }

}
