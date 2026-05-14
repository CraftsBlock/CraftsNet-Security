package de.craftsblock.cnet.modules.security.token.event.cache;

import de.craftsblock.craftscore.event.Event;

/**
 * Base event that signals a cache revalidation request inside the security module.
 * <p>
 * This event is used to indicate that cached data (such as tokens or groups)
 * may no longer be up to date and should be refreshed or invalidated by
 * registered listeners.
 * <p>
 * Subclasses define whether the revalidation targets a specific subject
 * or the entire cache.
 *
 * @param <T> The type of the cached subject affected by this event
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see RevalidateGroupCacheEvent
 * @see RevalidateTokenCacheEvent
 * @since 1.0.0
 */
public abstract sealed class RevalidateCacheEvent<T> extends Event
        permits RevalidateGroupCacheEvent, RevalidateTokenCacheEvent {

    /**
     * Returns the subject associated with this cache revalidation event.
     * <p>
     * The subject typically represents the specific entity (e.g. token or group)
     * whose cached state should be revalidated. If no subject is present,
     * the entire cache may be considered affected.
     *
     * @return The affected subject, or {@code null} if not applicable.
     */
    public T getSubject() {
        return null;
    }

    /**
     * Indicates whether this event targets a specific cached subject.
     *
     * @return {@code true} if a subject is present, otherwise {@code false}.
     */
    public boolean hasSubject() {
        return false;
    }

    /**
     * Cache revalidation events must not be executed asynchronously.
     * <p>
     * This ensures that cache state remains consistent during event processing.
     *
     * @return {@code false} always, as async execution is disallowed.
     */
    @Override
    protected boolean isAsyncAllowed() {
        return false;
    }

}
