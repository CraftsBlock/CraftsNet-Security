package de.craftsblock.cnet.modules.security.listeners;

import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.chains.AuthChain;
import de.craftsblock.cnet.modules.security.events.auth.AuthFailedEvent;
import de.craftsblock.cnet.modules.security.events.auth.AuthSuccessEvent;
import de.craftsblock.cnet.modules.security.events.auth.GenericAuthResultEvent;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.http.Response;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.EventWithCancelReason;
import de.craftsblock.craftsnet.events.requests.PreRequestEvent;
import de.craftsblock.craftsnet.events.requests.routes.RouteRequestEvent;
import de.craftsblock.craftsnet.events.requests.shares.ShareRequestEvent;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

/**
 * The PreRequestListener class listens for pre-request events and processes
 * authentication chains to determine if an incoming request should be allowed.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.1.1
 * @since 1.0.0-SNAPSHOT
 */
@AutoRegister(startup = Startup.LOAD)
public class PreRequestListener implements ListenerAdapter {

    private final CraftsNet craftsNet;

    /**
     * Constructs a new {@link PreRequestEvent}.
     *
     * @param craftsNet The {@link CraftsNet} instance bound to this {@link ListenerAdapter}.
     */
    public PreRequestListener(CraftsNet craftsNet) {
        this.craftsNet = craftsNet;
    }

    /**
     * Handles the {@link PreRequestEvent}. This method is triggered when a pre-request
     * event occurs and processes the authentication chains.
     *
     * @param event The {@link PreRequestEvent} containing information about the request.
     * @throws InvocationTargetException If an error occurs while calling / processing the event system
     * @throws IllegalAccessException    If an error occurs while calling / processing the event system
     */
    @EventHandler
    public void handleAuthChains(PreRequestEvent event) throws InvocationTargetException, IllegalAccessException {
        if (event.isCancelled()) return;

        Exchange exchange = event.getExchange();
        final Request request = exchange.request();

        GenericAuthResultEvent authEvent = new AuthSuccessEvent(exchange);

        // Iterate through each authentication chain
        for (AuthChain chain : CNetSecurity.getAuthChainManager()) {
            // Authenticate the incoming request using the current chain
            AuthResult result = chain.authenticate(exchange);

            // Continue if the authentication was cancelled
            if (!result.isCancelled()) continue;

            event.setCancelled(true); // Cancel the event
            authEvent = new AuthFailedEvent(exchange);

            // Send an error response back to the client
            Response response = exchange.response();
            if (!response.headersSent()) response.setCode(result.getCode());
            response.print(Json.empty().set("status", String.valueOf(result.getCode()))
                    .set("message", result.getCancelReason()));

            craftsNet.logger().debug("%s %s from %s \u001b[38;5;9m[%s]".formatted(
                    request.getHttpMethod(),
                    request.getRawUrl(),
                    request.getIp(),
                    "AUTH FAILED"
            ));

            break;
        }

        CNetSecurity.callEvent(authEvent);
    }

    /**
     * Handles the {@link RouteRequestEvent}. This method is triggered when a route request
     * event occurs and processes the rate limit chain.
     *
     * @param event The {@link RouteRequestEvent} containing information about the request.
     */
    @EventHandler(priority = EventPriority.HIGH)
    public void handleRateLimiter(RouteRequestEvent event) {
        handleRateLimiter(event, event.getExchange());
    }

    /**
     * Handles the {@link ShareRequestEvent}. This method is triggered when a share request
     * event occurs and processes the rate limit chain.
     *
     * @param event The {@link ShareRequestEvent} containing information about the share request.
     */
    @EventHandler(priority = EventPriority.HIGH)
    public void handleRateLimiter(ShareRequestEvent event) {
        handleRateLimiter(event, event.getExchange());
    }

    /**
     * Processes the rate limit chain.
     *
     * @param event    The {@link EventWithCancelReason} that was fired.
     * @param exchange The {@link Exchange} containing information about the request.
     */
    public void handleRateLimiter(EventWithCancelReason event, Exchange exchange) {
        if (CNetSecurity.getRateLimitManager().isRateLimited(exchange)) {
            // Cancel the event
            event.setCancelled(true);
            event.setCancelReason("RATELIMITED");

            // Send an error response back to the client
            exchange.response().print(Json.empty().set("status", "429").set("message", "You have been rate limited!"));
        }
    }

}
