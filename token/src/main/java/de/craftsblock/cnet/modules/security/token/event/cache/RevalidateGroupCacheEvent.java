package de.craftsblock.cnet.modules.security.token.event.cache;

import de.craftsblock.cnet.modules.security.token.event.cache.RevalidateCacheEvent;

public final class RevalidateGroupCacheEvent extends RevalidateCacheEvent<String> {

    private final String subject;

    public RevalidateGroupCacheEvent() {
        this(null);
    }

    public RevalidateGroupCacheEvent(String subject) {
        this.subject = subject;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public boolean hasSubject() {
        return subject != null;
    }

}
