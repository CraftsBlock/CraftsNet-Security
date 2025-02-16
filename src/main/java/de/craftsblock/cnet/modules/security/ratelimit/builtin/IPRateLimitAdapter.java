package de.craftsblock.cnet.modules.security.ratelimit.builtin;

import de.craftsblock.cnet.modules.security.AddonEntrypoint;
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
 * @version 1.0.0
 * @see RateLimitAdapter
 * @see RateLimitIndex
 * @since 1.0.0-SNAPSHOT
 */
public class IPRateLimitAdapter extends RateLimitAdapter {

    /**
     * Constructs a new {@link IPRateLimitAdapter} with the default rate limit of one request per period.
     *
     * @param parent The {@link AddonEntrypoint} representing the parent addon using this adapter.
     */
    public IPRateLimitAdapter(AddonEntrypoint parent) {
        super("IP", 500);
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
