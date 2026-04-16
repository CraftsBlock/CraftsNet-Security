package de.craftsblock.cnet.modules.security.token.event.cache;

import de.craftsblock.craftscore.event.Event;

public sealed class RevalidateCacheEvent<T> extends Event
        permits RevalidateGroupCacheEvent, RevalidateTokenCacheEvent {

    public T getSubject() {
        return null;
    }

    public boolean hasSubject() {
        return false;
    }

}
