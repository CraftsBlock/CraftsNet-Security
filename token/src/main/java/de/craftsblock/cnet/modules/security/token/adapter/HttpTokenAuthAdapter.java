package de.craftsblock.cnet.modules.security.token.adapter;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.adapter.AuthAdapter;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.TokenManager;
import de.craftsblock.cnet.modules.security.token.event.TokenUsedEvent;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.session.Session;
import org.jetbrains.annotations.NotNull;

import java.util.EnumMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * HTTP authentication adapter that resolves and validates security tokens
 * from different HTTP request locations.
 * <p>
 * This adapter supports multiple token sources such as headers, cookies,
 * and session attributes. It iterates through all configured
 * {@link HttpTokenAuthType} entries and attempts to authenticate the
 * incoming request using the first valid token found.
 * <p>
 * Once a token is successfully validated, a {@link TokenUsedEvent} is
 * emitted and the token is stored in the exchange context for further
 * processing within the request lifecycle.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class HttpTokenAuthAdapter implements AuthAdapter.Http {

    /**
     * Expected authentication scheme prefix used in HTTP Authorization headers.
     */
    public static final String HEADER_AUTH_TYPE = "bearer";

    private final @NotNull EnumMap<HttpTokenAuthType, String> authTypes;

    /**
     * Creates a new HTTP token authentication adapter.
     *
     * @param authTypes Mapping of authentication types to their
     *                  respective request locations.
     */
    public HttpTokenAuthAdapter(@NotNull EnumMap<HttpTokenAuthType, String> authTypes) {
        this.authTypes = authTypes;
    }

    /**
     * Attempts to authenticate the given HTTP exchange by checking
     * all configured token sources.
     * <p>
     * The method evaluates each configured {@link HttpTokenAuthType}
     * and returns the first successful authentication result. If no
     * token is found or validation fails, an appropriate failure or
     * skip result is returned.
     *
     * @param exchange The HTTP exchange to authenticate.
     * @return The authentication result.
     */
    @Override
    public AuthResult authenticate(Exchange exchange) {
        AtomicReference<AuthResult> authResultReference = new AtomicReference<>();
        synchronized (authTypes) {
            if (authTypes.isEmpty()) {
                CraftsNetSecurity.getInstance().getLogger().warning("No http token auth type is set up!");
                return AuthResult.failure("Not allowed!");
            }

            authTypes.forEach((authType, location) -> {
                AuthResult previous = authResultReference.get();
                if (previous != null && !previous.isSkip()) {
                    return;
                }

                AuthResult result = authenticate(exchange, authType, location);
                authResultReference.set(result);
            });
        }

        AuthResult result = authResultReference.get();
        if (result == null || !result.isOk()) {
            return result != null && result.isFailure() ? result : AuthResult.failure("Not allowed!");
        }

        return AuthResult.ok();
    }

    /**
     * Attempts to authenticate a request using a specific token source.
     * <p>
     * This method extracts the raw token depending on the configured
     * {@link HttpTokenAuthType}, validates it via the {@link TokenManager},
     * and stores the resulting token in the exchange context if valid.
     *
     * @param exchange The HTTP exchange.
     * @param authType The token source type.
     * @param location The location key (header name, cookie name, or session key).
     * @return The authentication result.
     */
    public AuthResult authenticate(Exchange exchange, HttpTokenAuthType authType, String location) {
        final Request request = exchange.request();
        final Session session = exchange.session();

        String plainToken = switch (authType) {
            case HEADER -> {
                String auth_header = request.getHeader(location);
                if (auth_header == null) {
                    yield null;
                }

                String[] header = auth_header.split(" ", 2);
                if (header.length != 2 || !HEADER_AUTH_TYPE.equalsIgnoreCase(header[0])) {
                    yield HEADER_AUTH_TYPE;
                }

                yield header[1];
            }
            case COOKIE -> {
                var cookies = request.getCookies();
                yield cookies.containsKey(location) ? cookies.get(location).getValue() : null;
            }
            case SESSION -> session.getTyped(location, String.class);
        };

        if (plainToken == null || plainToken.isBlank()) {
            return AuthResult.skip();
        }

        Token token = TokenManager.getInstance().getValidated(plainToken);
        if (token == null) {
            return AuthResult.failure("Not allowed! 2");
        }

        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenUsedEvent(token));
        exchange.context().put(token);
        return AuthResult.ok();
    }

}
