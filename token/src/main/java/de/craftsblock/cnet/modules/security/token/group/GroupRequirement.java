package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.craftsnet.api.RouteRegistry;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.requirements.web.WebRequirement;
import de.craftsblock.craftsnet.api.requirements.websocket.WebSocketRequirement;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;

import java.lang.annotation.Annotation;

/**
 * A requirement that is only used for the requirement system to
 * detect the {@link RequireGroup} requirement. In this class is
 * no logic which validates the groups.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see GroupResolveMiddleware
 * @since 1.0.4
 */
public sealed interface GroupRequirement permits GroupRequirement.Http, GroupRequirement.WebSocket {

    /**
     * The http version of the {@link GroupRequirement}.
     */
    @AutoRegister
    final class Http extends WebRequirement implements GroupRequirement {

        /**
         * Constructs a new http requirement.
         */
        public Http() {
            super(RequireGroup.class);
        }

        /**
         * Checks if this requirement applies. Return always true
         * as this only is needed for the {@link RequireGroup} to
         * be detected.
         *
         * @param request the storage instance
         * @param mapping the route mapping instance
         * @return Always {@code true}.
         */
        @Override
        public boolean applies(Request request, RouteRegistry.EndpointMapping mapping) {
            return true;
        }

    }

    /**
     * The web socket version of the {@link GroupRequirement}.
     */
    @AutoRegister
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements GroupRequirement {

        /**
         * Constructs a new web socket requirement.
         */
        public WebSocket() {
            super(RequireGroup.class);
        }

        /**
         * Checks if this requirement applies. Return always true
         * as this only is needed for the {@link RequireGroup} to
         * be detected.
         *
         * @param client  the storage instance
         * @param mapping the route mapping instance
         * @return Always {@code true}.
         */
        @Override
        public boolean applies(WebSocketClient client, RouteRegistry.EndpointMapping mapping) {
            return true;
        }

    }

}
