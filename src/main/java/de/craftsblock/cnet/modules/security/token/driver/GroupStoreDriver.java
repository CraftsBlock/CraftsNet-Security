package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.group.Group;

import java.util.Collection;

public non-sealed interface GroupStoreDriver extends Driver {

    default void reload() {
        CraftsNetSecurity.getGroupManager().clearCache();
    }

    boolean existsGroup(String name);

    Group loadGroup(String name);

    void saveGroup(Group group);

    default void deleteGroup(String name) {
        this.deleteGroup(loadGroup(name));
    }

    void deleteGroup(Group group);

    Collection<String> getAllGroupNames();

}
