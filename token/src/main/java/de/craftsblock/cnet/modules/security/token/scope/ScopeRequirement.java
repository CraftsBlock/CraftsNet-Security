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

/**
 * Requirement bridge for scope-based access control in route mappings.
 * <p>
 * This component integrates scope-based security constraints into the
 * CraftsNet routing system. It allows endpoints to declare required scopes
 * via annotations, which are then injected into the request or socket context
 * during routing evaluation.
 * <p>
 * The injected {@link ScopeRequest} can later be consumed by the authentication
 * and authorization chain to enforce access restrictions based on token scopes.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
public sealed interface ScopeRequirement
        permits ScopeRequirement.Http, ScopeRequirement.WebSocket {

    /**
     * Injects required scope information from the route mapping into the
     * execution context.
     * <p>
     * If the mapping contains the configured annotation, the declared scope
     * values are extracted and stored inside a {@link ScopeRequest}. Otherwise,
     * an empty scope requirement is stored.
     *
     * @param context The execution context of the request or socket
     * @param mapping The route mapping containing annotation metadata
     * @return {@code true} always, indicating successful injection
     */
    default boolean injectRequest(Context context, RouteRegistry.EndpointMapping mapping) {
        if (mapping.isPresent(getAnnotation(), "value")) {
            List<String> scopes = mapping.getRequirements(getAnnotation(), "value");
            context.put(new ScopeRequest(scopes));
        } else {
            context.put(new ScopeRequest(Collections.emptyList()));
        }

        return true;
    }

    /**
     * Returns the annotation type used to define required scopes on routes.
     *
     * @return The annotation class used for scope requirements
     */
    Class<? extends Annotation> getAnnotation();

    /**
     * HTTP implementation of {@link ScopeRequirement}.
     * <p>
     * Evaluates scope requirements during HTTP request processing and injects
     * them into the request context.
     */
    @AutoRegister(startup = Startup.LOAD)
    final class Http extends WebRequirement implements ScopeRequirement {

        /**
         * Creates a new HTTP scope requirement handler.
         */
        public Http() {
            super(RequireScope.class);
        }

        /**
         * Evaluates whether this requirement applies to the given HTTP request
         * and injects scope metadata into the request context.
         *
         * @param request The incoming HTTP request
         * @param mapping The endpoint mapping
         * @return {@code true} always, as the requirement only performs injection
         */
        @Override
        public boolean applies(Request request, RouteRegistry.EndpointMapping mapping) {
            return injectRequest(request.getExchange().context(), mapping);
        }

    }

    /**
     * WebSocket implementation of {@link ScopeRequirement}.
     * <p>
     * Evaluates scope requirements during WebSocket handshake and message
     * processing and injects them into the socket context.
     */
    @AutoRegister(startup = Startup.LOAD)
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements ScopeRequirement {

        /**
         * Creates a new WebSocket scope requirement handler.
         */
        public WebSocket() {
            super(RequireScope.class);
        }

        /**
         * Evaluates whether this requirement applies to the given WebSocket client
         * and injects scope metadata into the socket context.
         *
         * @param client  The connected WebSocket client
         * @param mapping The endpoint mapping
         * @return {@code true} always, as the requirement only performs injection
         */
        @Override
        public boolean applies(WebSocketClient client, RouteRegistry.EndpointMapping mapping) {
            return injectRequest(client.getContext(), mapping);
        }

    }

}
