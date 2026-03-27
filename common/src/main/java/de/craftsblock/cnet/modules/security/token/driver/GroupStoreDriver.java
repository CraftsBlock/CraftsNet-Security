package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.group.Group;
import de.craftsblock.cnet.modules.security.token.group.GroupManager;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;

public non-sealed interface GroupStoreDriver extends Driver {

    default void reload() {
        GroupManager.getInstance().clearCache();
    }

    boolean existsGroup(@NotNull String name);

    Group loadGroup(@NotNull String name);

    void saveGroup(@NotNull Group group);

    default void deleteGroup(@NotNull String name) {
        this.deleteGroup(loadGroup(name));
    }

    void deleteGroup(@NotNull Group group);

    @NotNull Collection<String> getAllGroupNames();

}
