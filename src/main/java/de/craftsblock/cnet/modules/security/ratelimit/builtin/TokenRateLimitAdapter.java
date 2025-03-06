package de.craftsblock.cnet.modules.security.ratelimit.builtin;

import de.craftsblock.cnet.modules.security.auth.token.Token;
import de.craftsblock.cnet.modules.security.ratelimit.RateLimitAdapter;
import de.craftsblock.cnet.modules.security.ratelimit.RateLimitIndex;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.session.Session;
import org.jetbrains.annotations.Nullable;

/**
 * The {@link TokenRateLimitAdapter} is a builtin implementation of {@link RateLimitAdapter}.
 * It enforces rate limiting based on the authentication token stored in the {@link Session}.
 * <p>
 * Each unique token is tracked as a {@link RateLimitIndex}, and rate limits are applied individually.
 * </p>
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.1
 * @see RateLimitAdapter
 * @see RateLimitIndex
 * @see Token
 * @since 1.0.0-SNAPSHOT
 */
public class TokenRateLimitAdapter extends RateLimitAdapter {

    /**
     * The id of the {@link TokenRateLimitAdapter}.
     */
    public static final String ID = "TOKEN";

    /**
     * Constructs a new {@link TokenRateLimitAdapter} with the default rate limit of 60 requests per period.
     *
     * @param max The maximum number of requests allowed within the expiration period.
     */
    public TokenRateLimitAdapter(long max) {
        super(ID, max);
    }

    /**
     * Constructs a new {@link TokenRateLimitAdapter} with the default rate limit of 60 requests per period.
     *
     * @param max    The maximum number of requests allowed within the expiration period.
     * @param expire The expiration time in milliseconds (must be greater than 0 and less than or equal to {@link #MAX_EXPIRE_MILLIS}).
     */
    public TokenRateLimitAdapter(long max, long expire) {
        super(ID, max, expire);
    }

    /**
     * Constructs a new {@link TokenRateLimitAdapter} with the default rate limit of 60 requests per period.
     *
     * @param max     The maximum number of requests allowed within the expiration period.
     * @param expire  The expiration time in milliseconds (must be greater than 0 and less than or equal to {@link #MAX_EXPIRE_MILLIS}).
     * @param headers Whether the rate limiting headers should be included in the response.
     */
    public TokenRateLimitAdapter(long max, long expire, boolean headers) {
        super(ID, max, expire, headers);
    }

    /**
     * Adapts the given {@link Request} into a {@link RateLimitIndex} based on the authentication token stored in the {@link Session}.
     * <p>
     * If the session storage does not contain a valid authentication token, the method returns {@code null}.
     * </p>
     *
     * @param request The {@link Request} to adapt.
     * @param session The {@link Session} associated with the request, expected to contain the authentication token.
     * @return A {@link RateLimitIndex} representing the token, or {@code null} if no token is found.
     */
    @Override
    public @Nullable RateLimitIndex adapt(Request request, Session session) {
        if (!session.containsKey("auth.token")) return null;
        return RateLimitIndex.of(this, session.getAsType("auth.token", Token.class));
    }

}
