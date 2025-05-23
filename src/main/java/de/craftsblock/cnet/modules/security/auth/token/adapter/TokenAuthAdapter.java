package de.craftsblock.cnet.modules.security.auth.token.adapter;

import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthAdapter;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.auth.token.Token;
import de.craftsblock.cnet.modules.security.auth.token.TokenManager;
import de.craftsblock.cnet.modules.security.events.auth.token.TokenUsedEvent;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.http.cookies.Cookie;
import de.craftsblock.craftsnet.api.session.Session;
import org.jetbrains.annotations.Nullable;

import java.util.EnumMap;
import java.util.Map;

/**
 * The {@link TokenAuthAdapter} class implements the {@link AuthAdapter} interface to provide authentication
 * functionality using bearer tokens.
 * <p>
 * This adapter extracts the token from the Authorization header of a http request,
 * validates it, and performs authentication by checking the token's validity
 * against the stored tokens managed by the {@link TokenManager}.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.4
 * @see TokenAuthType
 * @see TokenUsedEvent
 * @since 1.0.0-SNAPSHOT
 */
public class TokenAuthAdapter implements AuthAdapter {

    /**
     * The expected authorization type for bearer tokens.
     */
    public static final String HEADER_AUTH_TYPE = "bearer";

    private final EnumMap<TokenAuthType, String> authTypes = new EnumMap<>(TokenAuthType.class);

    private String tokenSessionKey = null;

    /**
     * Enables token authentication for the given authentication type using a default name.
     * <p>
     * For {@link TokenAuthType#HEADER}, the default name "Authorization" is used.
     * For {@link TokenAuthType#COOKIE} and {@link TokenAuthType#SESSION}, no default name is provided and an
     * {@link IllegalStateException} is thrown.
     * </p>
     *
     * @param type The token authentication type to enable.
     * @return The current instance of {@code TokenAuthAdapter} for method chaining.
     * @throws IllegalStateException if no default name is defined for the given authentication type.
     */
    public TokenAuthAdapter enable(TokenAuthType type) {
        return switch (type) {
            case HEADER -> enable(type, "Authorization");
            case COOKIE, SESSION -> throw new IllegalStateException("No default name for auth type " + type + " found!");
        };
    }

    /**
     * Enables token authentication for the given authentication type using the specified name.
     *
     * @param type The token authentication type to enable.
     * @param name The name of the header, cookie, or session attribute to use.
     * @return The current instance of {@code TokenAuthAdapter} for method chaining.
     */
    public TokenAuthAdapter enable(TokenAuthType type, String name) {
        this.authTypes.put(type, name);
        return this;
    }

    /**
     * Disables token authentication for the specified authentication type.
     *
     * @param type The token authentication type to disable.
     * @return The current instance of {@code TokenAuthAdapter} for method chaining.
     */
    public TokenAuthAdapter disable(TokenAuthType type) {
        this.authTypes.remove(type);
        return this;
    }

    /**
     * Checks if token authentication is enabled for the specified authentication type.
     *
     * @param type The token authentication type to check.
     * @return {@code true} if the authentication type is enabled, {@code false} otherwise.
     */
    public boolean isEnabled(TokenAuthType type) {
        return this.authTypes.containsKey(type);
    }

    /**
     * Sets the key where the used token should be stored in the session
     * of the exchange. If the session key is {@code null} the token will
     * not be stored in the session.
     *
     * @param sessionKey The key where the token should be stored.
     */
    public void setTokenSessionKey(@Nullable String sessionKey) {
        this.tokenSessionKey = sessionKey;
    }

    /**
     * Retrieves the key where the used token is stored inside the session.
     * If the token is not stored anywhere in the session this method returns
     * {@code null}.
     *
     * @return The key where the token is stored, or {@code null} when the token
     * is not stored in the session.
     */
    public @Nullable String getTokenSessionKey() {
        return tokenSessionKey;
    }

    /**
     * Authenticates the user based on the provided token in the request.
     * <p>
     * This method checks for the presence of the Authorization header and validates
     * the token format. If the token is valid, it retrieves the corresponding
     * {@link Token} from the {@link CNetSecurity} and verifies the token's
     * secret using BCrypt. If any validation fails, the authentication result is
     * marked as failed.
     *
     * @param result   The {@link AuthResult} object where the authentication result will be stored.
     * @param exchange The {@link Exchange} object representing the HTTP request.
     */
    @Override
    public void authenticate(AuthResult result, Exchange exchange) {
        if (result.isCancelled()) return;

        if (authTypes.isEmpty()) {
            failAuth(result, 501, "No auth type has been set up on the server!");
            return;
        }

        for (Map.Entry<TokenAuthType, String> entry : authTypes.entrySet()) {
            TokenAuthType type = entry.getKey();
            String name = entry.getValue();
            if (handle(result, exchange, type, name)) return;
        }

        if (result.isCancelled()) return;
        failAuth(result, 401, "Auth not present or wrong auth type!");
    }

    /**
     * Handles the authentication process for a specific token authentication type.
     *
     * @param result   The {@link AuthResult} object to update with authentication status.
     * @param exchange The {@link Exchange} object representing the HTTP request and session.
     * @param type     The token authentication type (e.g., HEADER, COOKIE, SESSION).
     * @param name     The name of the header, cookie, or session attribute to extract the token from.
     * @return {@code true} if the authentication process for this token type has been completed (successfully or not),
     * or {@code false} if the token was not found and further processing is required.
     */
    private boolean handle(AuthResult result, Exchange exchange, TokenAuthType type, String name) {
        if (result.isCancelled()) return true;

        final Request request = exchange.request();
        final Session session = exchange.session();

        String secret = switch (type) {
            case HEADER -> {
                // Retrieve the authorization header from the request
                String auth_header = request.getHeader(name);

                // Check if the header is present
                if (auth_header == null || auth_header.isBlank()) yield null;

                // Split the auth header and check if it has two values and is of the correct type
                String[] header = auth_header.split(" ");
                if (header.length != 2 || !HEADER_AUTH_TYPE.equalsIgnoreCase(header[0])) {
                    failAuth(result, 400, "No valid auth token present!");
                    yield null;
                }

                // Extract the token from the authorization header
                yield header[1];
            }
            case COOKIE -> request.getCookies().getOrDefault(name, new Cookie(name, null)).getValue();
            case SESSION -> session.getAsType(name, String.class);
        };

        if (result.isCancelled()) return true;
        if (secret == null || secret.isBlank()) return false;

        String url = request.getUrl();
        String domain = request.getDomain();
        HttpMethod method = request.getHttpMethod();
        Token token = CNetSecurity.getTokenManager().getValidatedToken(url, domain, method, secret);
        if (token == null) {
            failAuth(result, "You do not have access to this ressource!");
            return true;
        }

        try {
            if (tokenSessionKey != null && !tokenSessionKey.isBlank())
                session.put(tokenSessionKey, token);

            CNetSecurity.callEvent(new TokenUsedEvent(token, type));
        } catch (Exception e) {
            failAuth(result, 500, "Failed to verify your token!");
            CNetSecurity.getAddonEntrypoint().logger().error(e, "Failed to verify the api token!");
        }
        return true;
    }

}
