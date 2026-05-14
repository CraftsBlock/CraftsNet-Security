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

/**
 * Central manager responsible for lifecycle handling of {@link Group} instances.
 * <p>
 * This manager acts as a bridge between the in-memory cache and the underlying
 * {@link GroupStoreDriver}. It provides creation, update, retrieval, deletion,
 * and cache invalidation functionality for security groups.
 * <p>
 * Internally, a small LRU cache is used to reduce repeated driver access and
 * improve lookup performance for frequently used groups.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see Group
 * @since 1.0.0
 */
public class GroupManager {

    private final LruCache<String, Group> groupCache;

    /**
     * Creates a new {@code GroupManager} with a default cache size.
     */
    public GroupManager() {
        this(25);
    }

    /**
     * Creates a new {@code GroupManager} with the specified cache size.
     *
     * @param cacheSize The maximum number of cached groups
     */
    public GroupManager(int cacheSize) {
        this.groupCache = new LruCache<>(cacheSize);
    }

    /**
     * Creates a new group or updates an existing one using the provided updater.
     * <p>
     * If the group already exists, it is loaded and passed to the updater.
     * Otherwise, a new group is created, initialized, and persisted.
     *
     * @param name    The name of the group
     * @param updater A consumer used to modify the group instance
     * @return The created or updated {@link Group}
     */
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

    /**
     * Creates a new group with the given scopes and persists it.
     *
     * @param name   The name of the group
     * @param scopes The scopes assigned to the group
     * @return The newly created {@link Group}
     */
    public synchronized @NotNull Group create(@NotNull String name, @NotNull String @NotNull ... scopes) {
        Group group = createNotSaved(name, scopes);
        GroupStoreDriver driver = StoreDriver.getInstance();

        driver.saveGroup(group);
        return group;
    }

    /**
     * Creates a group instance without persisting it to the store.
     * <p>
     * If the group already exists in cache, the cached instance is returned.
     *
     * @param name   The group name
     * @param scopes The initial scopes
     * @return The created or cached {@link Group}
     */
    private synchronized @NotNull Group createNotSaved(@NotNull String name, @NotNull String @NotNull ... scopes) {
        Group existing = get(name);
        if (existing != null) {
            return existing;
        }

        Group group = new Group(name, Arrays.asList(scopes));
        groupCache.put(name, group);
        return group;
    }

    /**
     * Updates an existing group using the provided updater function.
     *
     * @param name    The name of the group
     * @param updater A consumer modifying the group instance
     * @return The updated {@link Group}, or {@code null} if it does not exist
     */
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

    /**
     * Retrieves a group by name, using the cache if available.
     *
     * @param name The group name
     * @return The {@link Group}, or {@code null} if not found
     */
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

    /**
     * Deletes a group from both the persistent store and the cache.
     *
     * @param group The group to delete
     */
    public synchronized void delete(@NotNull Group group) {
        this.delete(group.name());
    }

    /**
     * Deletes a group by name from both the persistent store and the cache.
     *
     * @param name The name of the group to delete
     */
    public synchronized void delete(@NotNull String name) {
        StoreDriver.getInstance().deleteGroup(name);
        removeCache(name);
    }

    /**
     * Clears the entire group cache.
     * <p>
     * This operation also triggers a {@link RevalidateGroupCacheEvent}
     * to notify listeners that cached group data has been invalidated.
     */
    public synchronized void clearCache() {
        groupCache.clear();
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new RevalidateGroupCacheEvent());
    }

    /**
     * Removes a group from the cache and triggers a cache revalidation event.
     *
     * @param group The group to remove
     */
    public synchronized void removeCache(@NotNull Group group) {
        this.removeCache(group.name());
    }

    /**
     * Removes a group from the cache by name and triggers a cache revalidation event.
     *
     * @param name The group name
     */
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

    /**
     * Returns the global {@link GroupManager} instance.
     *
     * @return The singleton group manager
     */
    public static @NotNull GroupManager getInstance() {
        return CraftsNetSecurityToken.getGroupManager();
    }

    /**
     * Replaces the global {@link GroupManager} instance.
     *
     * @param groupManager The new instance
     */
    public static void setInstance(@NotNull GroupManager groupManager) {
        CraftsNetSecurityToken.setGroupManager(groupManager);
    }

}
