package de.craftsblock.cnet.modules.security.ratelimit.builtin;

import de.craftsblock.cnet.modules.security.ratelimit.RateLimitAdapter;
import de.craftsblock.cnet.modules.security.ratelimit.RateLimitIndex;
import de.craftsblock.craftsnet.api.http.Request;
import de.craftsblock.craftsnet.api.session.Session;
import org.jetbrains.annotations.Nullable;

/**
 * The {@link IPRateLimitAdapter} is a builtin implementation of {@link RateLimitAdapter}.
 * It enforces rate limiting based on the client's IP address.
 * <p>
 * Each unique IP address is tracked as a {@link RateLimitIndex}, and rate limits are applied individually.
 * </p>
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.1
 * @see RateLimitAdapter
 * @see RateLimitIndex
 * @since 1.0.0-SNAPSHOT
 */
public class IPRateLimitAdapter extends RateLimitAdapter {

    /**
     * The id of the {@link IPRateLimitAdapter}.
     */
    public static final String ID = "IP";

    /**
     * Constructs a new {@link IPRateLimitAdapter} with the default rate limit of one request per period.
     *
     * @param max The maximum number of requests allowed within the expiration period.
     */
    public IPRateLimitAdapter(long max) {
        super(ID, max);
    }

    /**
     * Constructs a new {@link IPRateLimitAdapter} with the default rate limit of one request per period.
     *
     * @param max    The maximum number of requests allowed within the expiration period.
     * @param expire The expiration time in milliseconds (must be greater than 0 and less than or equal to {@link #MAX_EXPIRE_MILLIS}).
     */
    public IPRateLimitAdapter(long max, long expire) {
        super(ID, max, expire);
    }

    /**
     * Constructs a new {@link IPRateLimitAdapter} with the default rate limit of one request per period.
     *
     * @param max     The maximum number of requests allowed within the expiration period.
     * @param expire  The expiration time in milliseconds (must be greater than 0 and less than or equal to {@link #MAX_EXPIRE_MILLIS}).
     * @param headers Whether the rate limiting headers should be included in the response.
     */
    public IPRateLimitAdapter(long max, long expire, boolean headers) {
        super(ID, max, expire, headers);
    }

    /**
     * Adapts the given {@link Request} into a {@link RateLimitIndex} based on the client's IP address.
     *
     * @param request The {@link Request} to adapt.
     * @param session The {@link Session} associated with the request.
     * @return A {@link RateLimitIndex} representing the client's IP address, or {@code null} if adaptation fails.
     */
    @Override
    public @Nullable RateLimitIndex adapt(Request request, Session session) {
        return RateLimitIndex.of(this, request.getIp());
    }

}
