package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.CraftsNetSecurityToken;
import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.event.cache.RevalidateGroupCacheEvent;
import de.craftsblock.craftscore.cache.LruCache;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;

public class GroupManager {

    private final LruCache<String, Group> groupCache;

    public GroupManager() {
        this(25);
    }

    public GroupManager(int cacheSize) {
        this.groupCache = new LruCache<>(cacheSize);
    }

    public synchronized @NotNull Group createOrUpdate(@NotNull String name, @NotNull Consumer<@NotNull Group> updater) {
        GroupStoreDriver driver = StoreDriver.getInstance();
        if (driver.existsGroup(name)) {
            return Objects.requireNonNull(this.update(name, updater));
        }

        Group group = this.createNotSaved(name);
        updater.accept(group);
        driver.saveGroup(group);
        return group;
    }

    public synchronized @NotNull Group create(@NotNull String name, @NotNull String @NotNull ... scopes) {
        Group group = createNotSaved(name, scopes);
        GroupStoreDriver driver = StoreDriver.getInstance();

        driver.saveGroup(group);
        return group;
    }

    private synchronized @NotNull Group createNotSaved(@NotNull String name, @NotNull String @NotNull ... scopes) {
        Group existing = get(name);
        if (existing != null) {
            return existing;
        }

        Group group = new Group(name, Arrays.asList(scopes));
        groupCache.put(name, group);
        return group;
    }

    public synchronized @Nullable Group update(@NotNull String name, @NotNull Consumer<@NotNull Group> updater) {
        GroupStoreDriver driver = StoreDriver.getInstance();
        Group group = get(name);
        if (group == null) {
            return null;
        }

        updater.accept(group);
        driver.saveGroup(group);
        return group;
    }

    public synchronized @Nullable Group get(@NotNull String name) {
        if (groupCache.containsKey(name)) {
            return groupCache.get(name);
        }

        GroupStoreDriver driver = StoreDriver.getInstance();
        Group group = driver.loadGroup(name);
        if (group == null) {
            return null;
        }

        groupCache.put(name, group);
        return group;
    }

    public synchronized void delete(@NotNull Group group) {
        this.delete(group.name());
    }

    public synchronized void delete(@NotNull String name) {
        StoreDriver.getInstance().deleteGroup(name);
        removeCache(name);
    }

    public synchronized void clearCache() {
        groupCache.clear();
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new RevalidateGroupCacheEvent());
    }

    public synchronized void removeCache(@NotNull Group group) {
        this.removeCache(group.name());
    }

    public synchronized void removeCache(@NotNull String name) {
        Group removed = this.groupCache.remove(name);
        String realGroupName;
        if (removed == null) {
            realGroupName = name;
        } else {
            realGroupName = removed.name();
        }

        CraftsNetSecurity.getInstance().getListenerRegistry().call(new RevalidateGroupCacheEvent(realGroupName));
    }

    public static @NotNull GroupManager getInstance() {
        return CraftsNetSecurityToken.getGroupManager();
    }

    public static void setInstance(@NotNull GroupManager groupManager) {
        CraftsNetSecurityToken.setGroupManager(groupManager);
    }

}
