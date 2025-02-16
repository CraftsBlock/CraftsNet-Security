package de.craftsblock.cnet.modules.security.auth.token;

import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthAdapter;
import de.craftsblock.cnet.modules.security.auth.AuthResult;
import de.craftsblock.cnet.modules.security.events.auth.token.TokenUsedEvent;
import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.session.Session;

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
 * @version 1.0.0
 * @since 1.0.0-SNAPSHOT
 */
public class TokenAuthAdapter implements AuthAdapter {

    /**
     * The HTTP header name used for authorization.
     */
    public static final String AUTH_HEADER = "Authorization";

    /**
     * The expected authorization type for bearer tokens.
     */
    public static final String AUTH_TYPE = "bearer";

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
        final Request request = exchange.request();
        final Session session = exchange.session();

        // Retrieve the authorization header from the request
        String auth_header = request.getHeader(AUTH_HEADER);

        // Check if the header is present
        if (auth_header == null) {
            failAuth(result, 400, "Auth header not present or wrong auth type!");
            return;
        }

        // Split the auth header and check if it has two values and is of the correct type
        String[] header = auth_header.split(" ");
        if (header.length != 2 || !AUTH_TYPE.equalsIgnoreCase(header[0])) {
            failAuth(result, 400, "No valid auth token present!");
            return;
        }

        // Extract the token from the authorization header
        String key = header[1];

        String url = request.getUrl();
        String domain = request.getDomain();
        HttpMethod method = request.getHttpMethod();
        Token token = CNetSecurity.getTokenManager().getValidatedToken(url, domain, method, key);
        if (token == null) {
            failAuth(result, "You do not have access to this ressource!");
            return;
        }

        try {
            session.put("auth.token", token);
            CNetSecurity.callEvent(new TokenUsedEvent(token));
        } catch (Exception e) {
            failAuth(result, 500, "Failed to verify your token!");
            CNetSecurity.getAddonEntrypoint().logger().error(e, "Failed to verify the api token!");
        }
    }

}
