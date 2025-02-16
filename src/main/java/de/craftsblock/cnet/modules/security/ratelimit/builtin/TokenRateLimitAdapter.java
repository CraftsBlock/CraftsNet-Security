package de.craftsblock.cnet.modules.security.ratelimit.builtin;

import de.craftsblock.cnet.modules.security.AddonEntrypoint;
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
 * @version 1.0.0
 * @see RateLimitAdapter
 * @see RateLimitIndex
 * @see Token
 * @since 1.0.0-SNAPSHOT
 */
public class TokenRateLimitAdapter extends RateLimitAdapter {

    /**
     * Constructs a new {@code TokenRateLimitAdapter} with the default rate limit of 60 requests per period.
     *
     * @param parent The {@link AddonEntrypoint} representing the parent addon using this adapter.
     */
    public TokenRateLimitAdapter(AddonEntrypoint parent) {
        super("TOKEN", 60);
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
