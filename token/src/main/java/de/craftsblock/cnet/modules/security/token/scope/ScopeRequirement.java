package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.craftsnet.api.RouteRegistry;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.requirements.web.WebRequirement;
import de.craftsblock.craftsnet.api.requirements.websocket.WebSocketRequirement;
import de.craftsblock.craftsnet.api.websocket.WebSocketClient;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;

/**
 * A requirement that is only used for the requirement system to
 * detect the {@link RequireScope} requirement. In this class is
 * no logic which validates the scopes.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see ScopeResolveMiddleware
 * @since 1.0.4
 */
public sealed interface ScopeRequirement permits ScopeRequirement.Http, ScopeRequirement.WebSocket {

    /**
     * The http version of the {@link ScopeRequirement}.
     */
    @AutoRegister
    final class Http extends WebRequirement implements ScopeRequirement {

        /**
         * Constructs a new http requirement.
         */
        public Http() {
            super(RequireScope.class);
        }

        /**
         * Checks if this requirement applies. Return always true
         * as this only is needed for the {@link RequireScope} to
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
     * The web socket version of the {@link ScopeRequirement}.
     */
    @AutoRegister
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements ScopeRequirement {

        /**
         * Constructs a new web socket requirement.
         */
        public WebSocket() {
            super(RequireScope.class);
        }

        /**
         * Checks if this requirement applies. Return always true
         * as this only is needed for the {@link RequireScope} to
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
