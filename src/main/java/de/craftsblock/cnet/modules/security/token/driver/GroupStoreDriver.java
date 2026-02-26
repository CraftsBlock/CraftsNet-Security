package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.group.Group;

import java.util.Collection;

public non-sealed interface GroupStoreDriver extends AutoCloseable, Driver {

    default void reload() {
        CraftsNetSecurity.getGroupManager().clearCache();
    }

    boolean exists(String name);

    Group load(String name);

    void save(Group token);

    default void delete(String name) {
        this.delete(load(name));
    }

    void delete(Group group);

    Collection<String> getAllGroupNames();

    @Override
    void close();

}
