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

import java.util.EnumMap;
import java.util.concurrent.atomic.AtomicReference;

public class HttpTokenAuthAdapter implements AuthAdapter.Http {

    /**
     * The expected authorization type for bearer tokens.
     */
    public static final String HEADER_AUTH_TYPE = "bearer";

    private final EnumMap<HttpTokenAuthType, String> authTypes;

    public HttpTokenAuthAdapter(EnumMap<HttpTokenAuthType, String> authTypes) {
        this.authTypes = authTypes;
    }

    @Override
    public AuthResult authenticate(Exchange exchange) {
        if (authTypes == null || authTypes.isEmpty()) {
            CraftsNetSecurity.getInstance().getLogger().warning("No http token auth type is set up!");
            return AuthResult.failure("Not allowed!");
        }

        AtomicReference<AuthResult> authResultReference = new AtomicReference<>();
        authTypes.forEach((authType, location) -> {
            AuthResult previous = authResultReference.get();
            if (previous != null && !previous.isSkip()) {
                return;
            }

            AuthResult result = authenticate(exchange, authType, location);
            authResultReference.set(result);
        });

        AuthResult result = authResultReference.get();
        if (result == null || !result.isOk()) {
            return result != null && result.isFailure() ? result : AuthResult.failure("Not allowed!");
        }

        return AuthResult.ok();
    }

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

        Token token = TokenManager.getInstance().getValidatedToken(plainToken);
        if (token == null) {
            return AuthResult.failure("Not allowed! 2");
        }

        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenUsedEvent(token));
        exchange.context().put(token);
        return AuthResult.ok();
    }

}
