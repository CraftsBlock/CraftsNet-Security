package de.craftsblock.cnet.modules.security.token.event.cache;

public final class RevalidateTokenCacheEvent extends RevalidateCacheEvent<Long> {

    private final long subject;

    public RevalidateTokenCacheEvent() {
        this(-1);
    }

    public RevalidateTokenCacheEvent(long subject) {
        this.subject = subject;
    }

    @Override
    public Long getSubject() {
        return subject;
    }

    @Override
    public boolean hasSubject() {
        return subject >= 0;
    }

}
