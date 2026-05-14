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

/**
 * Requirement bridge for group-based access control in route mappings.
 * <p>
 * This component integrates group-based security constraints into the
 * CraftsNet routing system. It allows endpoints to declare required groups
 * via annotations, which are then injected into the request or socket context
 * during routing evaluation.
 * <p>
 * The injected {@link GroupRequest} can later be consumed by the security
 * authentication chain to enforce access restrictions based on token groups.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@ApiStatus.Internal
public sealed interface GroupRequirement
        permits GroupRequirement.Http, GroupRequirement.WebSocket {

    /**
     * Injects required group information from the route mapping into the
     * execution context.
     * <p>
     * If the mapping contains the configured annotation, the declared group
     * values are extracted and stored inside a {@link GroupRequest}. Otherwise,
     * an empty group requirement is stored.
     *
     * @param context The execution context of the request or socket
     * @param mapping The route mapping containing annotation metadata
     * @return {@code true} always, indicating successful injection
     */
    default boolean injectRequest(Context context, RouteRegistry.EndpointMapping mapping) {
        if (mapping.isPresent(getAnnotation(), "value")) {
            List<String> groups = mapping.getRequirements(getAnnotation(), "value");
            context.put(new GroupRequest(groups));
        } else {
            context.put(new GroupRequest(Collections.emptyList()));
        }

        return true;
    }

    /**
     * Returns the annotation type used to define required groups on routes.
     *
     * @return The annotation class used for group requirements
     */
    Class<? extends Annotation> getAnnotation();

    /**
     * HTTP implementation of {@link GroupRequirement}.
     * <p>
     * Evaluates group requirements during HTTP request processing and injects
     * them into the request context.
     */
    @AutoRegister(startup = Startup.LOAD)
    final class Http extends WebRequirement implements GroupRequirement {

        /**
         * Creates a new HTTP group requirement handler.
         */
        public Http() {
            super(RequireGroup.class);
        }

        /**
         * Evaluates whether this requirement applies to the given HTTP request
         * and injects group metadata into the request context.
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
     * WebSocket implementation of {@link GroupRequirement}.
     * <p>
     * Evaluates group requirements during WebSocket handshake processing and
     * injects them into the socket context.
     */
    @AutoRegister(startup = Startup.LOAD)
    final class WebSocket extends WebSocketRequirement<WebSocketClient> implements GroupRequirement {

        /**
         * Creates a new WebSocket group requirement handler.
         */
        public WebSocket() {
            super(RequireGroup.class);
        }

        /**
         * Evaluates whether this requirement applies to the given WebSocket client
         * and injects group metadata into the socket context.
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