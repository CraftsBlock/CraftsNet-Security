package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.Group;
import de.craftsblock.craftscore.json.Json;

import java.nio.file.Path;
import java.util.Collection;

public final class FileGroupStoreDriver extends AbstractFileStoreDriver implements GroupStoreDriver {

    public FileGroupStoreDriver(Path file) {
        super(file);
    }

    @Override
    public void reload() {
        GroupStoreDriver.super.reload();
        super.reload();
    }

    @Override
    public boolean exists(String name) {
        return this.json(json -> {
            return json.contains(name);
        });
    }

    @Override
    public Group load(String name) {
        Json group = this.json(json -> {
            return json.getJson(name);
        });

        if (group == null) {
            throw new IllegalStateException("Group for name %s not found".formatted(name));
        }

        return Group.fromJson(group);
    }

    @Override
    public void save(Group group) {
        this.json(json -> {
            json.set(group.name(), group.toJson());
            json.save(file);
        });
    }

    @Override
    public void delete(Group group) {
        this.json(json -> {
            json.remove(group.name());
            json.save(file);
        });
    }

    @Override
    public Collection<String> getAllGroupNames() {
        return this.json(json -> {
            return json.keySet();
        });
    }

}
