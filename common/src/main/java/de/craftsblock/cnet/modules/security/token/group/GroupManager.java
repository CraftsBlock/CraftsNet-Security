package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.craftscore.cache.Cache;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;

public class GroupManager {

    private final Cache<String, Group> groupCache;

    public GroupManager() {
        this(25);
    }

    public GroupManager(int cacheSize) {
        this.groupCache = new Cache<>(cacheSize);
    }

    public synchronized @NotNull Group createOrUpdateGroup(@NotNull String name, @NotNull Consumer<@NotNull Group> updater) {
        GroupStoreDriver driver = StoreDriver.getInstance();
        if (driver.existsGroup(name)) {
            return Objects.requireNonNull(this.updateGroup(name, updater));
        }

        Group group = this.createGroup(name);
        updater.accept(group);
        driver.saveGroup(group);
        return group;
    }

    public synchronized @NotNull Group createGroup(@NotNull String name, @NotNull String @NotNull ... scopes) {
        GroupStoreDriver driver = StoreDriver.getInstance();
        Group existing = getGroup(name);
        if (existing != null) {
            return existing;
        }

        Group group = new Group(name, Arrays.asList(scopes));
        driver.saveGroup(group);
        groupCache.put(name, group);
        return group;
    }

    public synchronized @Nullable Group updateGroup(@NotNull String name, @NotNull Consumer<@NotNull Group> updater) {
        GroupStoreDriver driver = StoreDriver.getInstance();
        Group group = getGroup(name);
        if (group == null) {
            return null;
        }

        updater.accept(group);
        driver.saveGroup(group);
        return group;
    }

    public synchronized @Nullable Group getGroup(@NotNull String name) {
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

    public synchronized void deleteGroup(@NotNull String name) {
        StoreDriver.getInstance().deleteGroup(name);
        groupCache.remove(name);
    }

    public synchronized void clearCache() {
        groupCache.clear();
    }

    public synchronized void removeCache(@NotNull Group group) {
        this.removeCache(group.name());
    }

    public synchronized void removeCache(@NotNull String name) {
        this.groupCache.remove(name);
    }

    public static @NotNull GroupManager getInstance() {
        return CraftsNetSecurity.getGroupManager();
    }

    public static void setInstance(@NotNull GroupManager groupManager) {
        CraftsNetSecurity.setGroupManager(groupManager);
    }

}
