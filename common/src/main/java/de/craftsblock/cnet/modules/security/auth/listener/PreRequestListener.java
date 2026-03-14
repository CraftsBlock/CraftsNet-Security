package de.craftsblock.cnet.modules.security.auth.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.HttpStatus;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.http.Response;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.autoregister.meta.constructors.FallbackConstructor;
import de.craftsblock.craftsnet.autoregister.meta.constructors.PreferConstructor;
import de.craftsblock.craftsnet.events.requests.PreRequestEvent;

@AutoRegister(startup = Startup.LOAD)
public record PreRequestListener(CraftsNet craftsNet, CraftsNetSecurity addon) implements AuthListener<Response>, ListenerAdapter {

    @PreferConstructor
    public PreRequestListener {
    }

    @FallbackConstructor
    public PreRequestListener(CraftsNet craftsNet) {
        this(craftsNet, CraftsNetSecurity.getInstance());
    }

    @EventHandler(priority = EventPriority.LOW, ignoreWhenCancelled = true)
    public void handlePreRequestEvent(PreRequestEvent event) {
        final Exchange exchange = event.getExchange();
        final Request request = exchange.request();

        this.authenticate(exchange, event, exchange.response(), ((response, result) -> {
            addon.getCraftsNet().getLogger().warning("%s %s from %s \u001b[38;5;9m[%s]".formatted(
                    request.getHttpMethod(),
                    request.getRawUrl(),
                    request.getIp(),
                    "AUTH FAILED"
            ));

            if (!response.headersSent()) {
                response.setStatus(HttpStatus.ClientError.BAD_REQUEST);
            }

            if (response.sendingFile()) {
                return;
            }

            response.print(Json.empty()
                    .set("success", false)
                    .set("error.code", result.getCode())
                    .set("error.message", result.getReason()));
        }));
    }

}
