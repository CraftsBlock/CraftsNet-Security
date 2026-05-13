package de.craftsblock.cnet.modules.security.token.event.cache;

/**
 * Event that signals a revalidation of the token cache inside the security module.
 * <p>
 * This event is fired when token-related cached data is potentially outdated
 * and needs to be refreshed. It can target a specific token or the entire
 * token cache depending on whether a subject is provided.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see RevalidateTokenCacheEvent
 * @since 1.0.0
 */
public final class RevalidateTokenCacheEvent extends RevalidateCacheEvent<Long> {

    private final long subject;

    /**
     * Creates a cache revalidation event affecting all tokens.
     */
    public RevalidateTokenCacheEvent() {
        this(-1);
    }

    /**
     * Creates a cache revalidation event for a specific token.
     *
     * @param subject The token ID to revalidate, or {@code -1} if the entire cache is affected.
     */
    public RevalidateTokenCacheEvent(long subject) {
        this.subject = subject;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the token ID associated with this event.
     */
    @Override
    public Long getSubject() {
        return subject;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Indicates whether this event targets a specific token instead of the full cache.
     */
    @Override
    public boolean hasSubject() {
        return subject >= 0;
    }

}
