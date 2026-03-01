package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.craftscore.cache.Cache;

import java.util.Arrays;
import java.util.function.Consumer;

public class GroupManager {

    private final Cache<String, Group> groupCache;

    public GroupManager() {
        this(25);
    }

    public GroupManager(int cacheSize) {
        this.groupCache = new Cache<>(cacheSize);
    }

    public synchronized Group createOrUpdateGroup(String name, Consumer<Group> updater) {
        GroupStoreDriver driver = CraftsNetSecurity.getStoreDriver();
        if (driver.existsGroup(name)) {
            return this.updateGroup(name, updater);
        }

        Group group = this.createGroup(name);
        updater.accept(group);
        driver.saveGroup(group);
        return group;
    }

    public synchronized Group createGroup(String name, String... scopes) {
        GroupStoreDriver driver = CraftsNetSecurity.getStoreDriver();
        Group existing = getGroup(name);
        if (existing != null) {
            return existing;
        }

        Group group = new Group(name, Arrays.asList(scopes));
        driver.saveGroup(group);
        groupCache.put(name, group);
        return group;
    }

    public synchronized Group updateGroup(String name, Consumer<Group> updater) {
        GroupStoreDriver driver = CraftsNetSecurity.getStoreDriver();
        Group group = getGroup(name);
        if (group == null) {
            return null;
        }

        updater.accept(group);
        driver.saveGroup(group);
        return group;
    }

    public synchronized Group getGroup(String name) {
        if (groupCache.containsKey(name)) {
            return groupCache.get(name);
        }

        GroupStoreDriver driver = CraftsNetSecurity.getStoreDriver();
        Group group = driver.loadGroup(name);
        if (group == null) {
            return null;
        }

        groupCache.put(name, group);
        return group;
    }

    public synchronized void deleteGroup(String name) {
        CraftsNetSecurity.getStoreDriver().deleteGroup(name);
        groupCache.remove(name);
    }

    public synchronized void clearCache() {
        groupCache.clear();
    }

}
