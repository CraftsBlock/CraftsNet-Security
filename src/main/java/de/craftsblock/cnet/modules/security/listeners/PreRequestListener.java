package de.craftsblock.cnet.modules.security.listeners;

import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.chains.AuthChain;
import de.craftsblock.craftscore.event.*;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.api.annotations.AutoRegister;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.events.EventWithCancelReason;
import de.craftsblock.craftsnet.events.requests.PreRequestEvent;
import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.craftsnet.events.requests.routes.RouteRequestEvent;
import de.craftsblock.craftsnet.events.requests.shares.ShareRequestEvent;

import java.io.IOException;

/**
 * The PreRequestListener class listens for pre-request events and processes
 * authentication chains to determine if an incoming request should be allowed.
 */
@AutoRegister
public class PreRequestListener implements ListenerAdapter {

    /**
     * Handles the {@link PreRequestEvent}. This method is triggered when a pre-request
     * event occurs and processes the authentication chains.
     *
     * @param event The {@link PreRequestEvent} containing information about the request.
     * @throws IOException If an error occurs while processing the request or response.
     */
    @EventHandler(priority = EventPriority.LOWEST)
    public void handleAuthChains(PreRequestEvent event) throws IOException {
        Exchange exchange = event.getExchange();

        // Iterate through each authentication chain
        for (AuthChain chain : CNetSecurity.getAuthChainManager()) {
            // Authenticate the incoming request using the current chain
            AuthResult result = chain.authenticate(exchange);

            // Check if the authentication was cancelled
            if (result.isCancelled()) {
                event.setCancelled(true); // Cancel the event
                // Send an error response back to the client
                exchange.response().print(Json.empty().set("error", result.getCancelReason()));
            }
        }
    }

    /**
     * Handles the {@link RouteRequestEvent}. This method is triggered when a route request
     * event occurs and processes the rate limit chain.
     *
     * @param event The {@link RouteRequestEvent} containing information about the request.
     * @throws IOException If an error occurs while processing the request or response.
     */
    @EventHandler(priority = EventPriority.HIGH)
    public void handleRateLimiter(RouteRequestEvent event) throws IOException {
        handleRateLimiter(event, event.getExchange());
    }

    /**
     * Handles the {@link ShareRequestEvent}. This method is triggered when a share request
     * event occurs and processes the rate limit chain.
     *
     * @param event The {@link ShareRequestEvent} containing information about the share request.
     * @throws IOException If an error occurs while processing the request or response.
     */
    @EventHandler(priority = EventPriority.HIGH)
    public void handleRateLimiter(ShareRequestEvent event) throws IOException {
        handleRateLimiter(event, event.getExchange());
    }

    /**
     * Processes the rate limit chain.
     *
     * @param event    The {@link EventWithCancelReason} that was fired.
     * @param exchange The {@link Exchange} containing information about the request.
     * @throws IOException If an error occurs while processing the request or response.
     */
    public void handleRateLimiter(EventWithCancelReason event, Exchange exchange) throws IOException {
        if (CNetSecurity.getRateLimitManager().isRateLimited(exchange)) {
            // Cancel the event
            event.setCancelled(true);
            event.setCancelReason("RATELIMITED");

            // Send an error response back to the client
            exchange.response().print(Json.empty().set("error", "You have been rate limited!"));
        }
    }

}
