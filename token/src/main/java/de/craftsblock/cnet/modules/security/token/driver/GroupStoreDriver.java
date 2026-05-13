package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.group.Group;
import de.craftsblock.cnet.modules.security.token.group.GroupManager;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;

/**
 * Persistence driver responsible for storing and managing {@link Group}
 * entities.
 * <p>
 * Implementations of this interface define how group data is persisted,
 * retrieved, and deleted. This may include storage backends such as SQL
 * databases, file-based systems, or in-memory structures.
 * <p>
 * The driver also provides a reload mechanism which integrates with the
 * {@link GroupManager} cache system.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public non-sealed interface GroupStoreDriver extends Driver {

    /**
     * Reloads the group cache managed by the {@link GroupManager GroupManager}.
     * <p>
     * This is typically used after external modifications to the underlying
     * storage to ensure consistency between the cache and persistence layer.
     */
    default void reload() {
        GroupManager.getInstance().clearCache();
    }

    /**
     * Checks whether a group with the given name exists in the storage.
     *
     * @param name The name of the group.
     * @return {@code true} if the group exists, otherwise {@code false}.
     */
    boolean existsGroup(@NotNull String name);

    /**
     * Loads a group by its name from the underlying storage.
     *
     * @param name The name of the group.
     * @return The loaded {@link Group} instance.
     */
    Group loadGroup(@NotNull String name);

    /**
     * Persists the given group into the underlying storage.
     *
     * @param group The group to save.
     */
    void saveGroup(@NotNull Group group);

    /**
     * Deletes a group by its name from the underlying storage.
     *
     * @param name The name of the group to delete.
     */
    default void deleteGroup(@NotNull String name) {
        this.deleteGroup(loadGroup(name));
    }

    /**
     * Deletes the given group from the underlying storage.
     *
     * @param group The group to delete.
     */
    void deleteGroup(@NotNull Group group);

    /**
     * Returns a collection of all available group names in the storage.
     *
     * @return A collection containing all group identifiers.
     */
    @NotNull Collection<String> getAllGroupNames();

}
