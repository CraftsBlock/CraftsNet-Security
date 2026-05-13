package de.craftsblock.cnet.modules.security.token.event.cache;

/**
 * Event that signals a revalidation of the group cache inside the security module.
 * <p>
 * This event is triggered when either a specific group or the entire group cache
 * needs to be refreshed. If a subject is provided, only the corresponding group
 * is affected; otherwise, a full cache revalidation is implied.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see RevalidateCacheEvent
 * @since 1.0.0
 */
public final class RevalidateGroupCacheEvent extends RevalidateCacheEvent<String> {

    private final String subject;

    /**
     * Creates a cache revalidation event targeting all groups.
     */
    public RevalidateGroupCacheEvent() {
        this(null);
    }

    /**
     * Creates a cache revalidation event for a specific group.
     *
     * @param subject The name of the group to revalidate, or {@code null}
     *                if the entire cache should be revalidated.
     */
    public RevalidateGroupCacheEvent(String subject) {
        this.subject = subject;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the group name associated with this event, if present.
     */
    @Override
    public String getSubject() {
        return subject;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Indicates whether this event targets a specific group.
     */
    @Override
    public boolean hasSubject() {
        return subject != null;
    }

}
