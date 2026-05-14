package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.Group;
import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;

import java.nio.file.Path;
import java.util.Collection;

/**
 * File-based implementation of the {@link GroupStoreDriver}.
 * <p>
 * This driver persists {@link Group} objects inside a JSON file structure,
 * where each group is stored as a top-level JSON entry keyed by its name.
 * <p>
 * It extends {@link AbstractFileStoreDriver} to reuse common file handling,
 * caching, and hot-reload functionality.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AbstractFileStoreDriver
 * @see GroupStoreDriver
 * @since 1.0.0
 */
public final class FileGroupStoreDriver extends AbstractFileStoreDriver implements GroupStoreDriver {

    /**
     * Creates a new file-based group store driver.
     *
     * @param file The file used for persisting group data.
     */
    FileGroupStoreDriver(Path file) {
        super(file);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reload() {
        GroupStoreDriver.super.reload();
        super.reload();
    }

    /**
     * {@inheritDoc}
     *
     * @param name {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean existsGroup(@NotNull String name) {
        return this.json(json -> {
            return json.contains(name);
        });
    }

    /**
     * {@inheritDoc}
     *
     * @param name {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public Group loadGroup(@NotNull String name) {
        Json group = this.json(json -> {
            return json.getJson(name);
        });

        if (group == null) {
            return null;
        }

        return Group.fromJson(group);
    }

    /**
     * {@inheritDoc}
     *
     * @param group {@inheritDoc}
     */
    @Override
    public void saveGroup(@NotNull Group group) {
        this.json(json -> {
            json.set(group.name(), group.toJson());
            json.save(file);
        });
    }

    /**
     * {@inheritDoc}
     *
     * @param group {@inheritDoc}
     */
    @Override
    public void deleteGroup(@NotNull Group group) {
        this.json(json -> {
            json.remove(group.name());
            json.save(file);
        });
    }

    /**
     * {@inheritDoc}
     *
     * @return {@inheritDoc}
     */
    @Override
    public @NotNull Collection<String> getAllGroupNames() {
        return this.json(json -> {
            return json.keySet();
        });
    }

}
