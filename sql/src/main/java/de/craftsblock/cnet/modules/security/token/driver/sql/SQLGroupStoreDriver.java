package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.Group;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.function.Supplier;

public final class SQLGroupStoreDriver extends AbstractSQLStoreDriver implements GroupStoreDriver {

    private SQLStoreDriver storeDriver;

    SQLGroupStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    void setStoreDriver(@NotNull SQLStoreDriver storeDriver) {
        if (this.storeDriver != null) {
            return;
        }

        this.storeDriver = storeDriver;
    }

    @Override
    public boolean existsGroup(@NotNull String name) {
        ensureOpen();

        return this.query(this.preparedStatement(
                "SELECT 1 FROM `cnet_security_groups` WHERE `name` = ? LIMIT 1;", name
        ), ResultSet::next);
    }

    @Override
    public Group loadGroup(@NotNull String name) {
        ensureOpen();

        String groupName = this.query(this.preparedStatement(
                "SELECT `name` FROM `cnet_security_groups` WHERE `name` = ?;",
                name
        ), result -> {
            if (result.next()) {
                return result.getString("name");
            }

            return null;
        });

        if (groupName == null) {
            return null;
        }

        Collection<String> scopes = this.queryCollection(this.preparedStatement(
                "SELECT `scope` FROM `cnet_security_group_scopes` WHERE `group`=?;", name
        ), "scope", String.class);

        return new Group(groupName, scopes);
    }

    @Override
    public void saveGroup(@NotNull Group group) {
        ensureOpen();
        this.update(this.preparedStatement(
                "INSERT IGNORE INTO `cnet_security_groups` (`name`) VALUES (?)",
                group.name()
        ));

        if (group.scopes().isEmpty()) {
            return;
        }

        persistScopes(group);
        unlinkScopes(group);
        this.storeDriver.getScopeDriver().cleanUpScopes();
    }

    private void unlinkScopes(Group group) {
        Set<String> groupScopes = new HashSet<>(group.scopes());
        Collection<String> unlinkedScopes = this.queryCollection(this.preparedStatement(
                        "SELECT `scope` FROM `cnet_security_group_scopes`"
                ), "scope", String.class)
                .parallelStream()
                .filter(scope -> !groupScopes.contains(scope))
                .toList();

        if (unlinkedScopes.isEmpty()) {
            return;
        }

        StringJoiner values = new StringJoiner(",");
        unlinkedScopes.forEach(ignored -> values.add("?"));

        this.update(this.preparedStatementList(
                "DELETE FROM `cnet_security_entity_scopes` WHERE `scope_id` IN (" +
                        "SELECT `id` FROM `cnet_security_scopes` WHERE value IN (%s))".formatted(values.toString()),
                unlinkedScopes
        ));
    }

    private void persistScopes(Group group) {
        Set<Long> known = new HashSet<>(this.queryCollection(this.preparedStatement(
                "SELECT `scope_id` FROM `cnet_security_entity_scopes` WHERE `group_id` = ?;",
                group.name()
        ), "scope_id", Long.class));

        Collection<Long> scopes = this.storeDriver.getScopeDriver()
                .saveScopes(group.scopes().toArray(String[]::new))
                .values().parallelStream()
                .filter(id -> !known.contains(id))
                .toList();

        if (scopes.isEmpty()) {
            return;
        }

        List<Object> params = new ArrayList<>(scopes.size() * 2);
        StringJoiner values = new StringJoiner(", ");

        for (Long id : scopes) {
            values.add("(?, ?)");
            params.add(id);
            params.add(group.name());
        }

        this.update(this.preparedStatementList(
                "INSERT IGNORE INTO `cnet_security_entity_scopes` (`scope_id`, `group_id`) VALUES " + values,
                params
        ));
    }

    @Override
    public void deleteGroup(@NotNull Group group) {
        ensureOpen();
        this.update(this.preparedStatement(
                "DELETE FROM `cnet_security_groups` WHERE `name`=?;",
                group
        ));

        this.storeDriver.getScopeDriver().cleanUpScopes();
    }

    @Override
    public @NotNull Collection<String> getAllGroupNames() {
        ensureOpen();
        return this.queryCollection(this.preparedStatement(
                "SELECT * FROM `cnet_security_groups`;"
        ), "name", String.class);
    }

}
