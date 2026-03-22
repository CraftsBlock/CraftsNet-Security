package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.Group;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.sql.ResultSet;
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

        return this.query(this.preparedStatement(
                """
                        SELECT
                            `group`.`name`,
                            `scope`.`value` AS `scope`
                        FROM `cnet_security_groups` `group`
                        LEFT JOIN `cnet_security_entity_scopes` `entity_scope` ON `entity_scope`.`group_id` = `group`.`name`
                        LEFT JOIN `cnet_security_scopes` `scope` ON `scope`.`id` = `entity_scope`.`scope_id`
                        WHERE `group`.`name` = ?;
                        """,
                name
        ), result -> {
            String groupName = null;
            Set<String> scopes = new HashSet<>();

            while (result.next()) {
                if (groupName == null) {
                    groupName = result.getString("name");
                }

                String scope = result.getString("scope");
                if (scope != null) {
                    scopes.add(scope);
                }
            }

            if (groupName == null) {
                return null;
            }

            return new Group(groupName, scopes);
        });
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

    private void persistScopes(Group group) {
        if (group.scopes().isEmpty()) {
            return;
        }

        Collection<Long> scopes = this.storeDriver.getScopeDriver()
                .saveScopes(group.scopes().toArray(String[]::new))
                .values();

        if (scopes.isEmpty()) {
            return;
        }

        final String groupName = group.name();
        this.updateBatch(
                this.preparedStatement(
                        "INSERT IGNORE INTO `cnet_security_entity_scopes` (`scope_id`, `group_id`) VALUES (?, ?);"
                ), scopes,
                (statement, scopeId) -> {
                    statement.setLong(1, scopeId);
                    statement.setString(2, groupName);
                }
        );
    }

    private void unlinkScopes(Group group) {
        if (group.scopes().isEmpty()) {
            return;
        }

        StringJoiner placeholders = new StringJoiner(",");
        group.scopes().forEach(s -> placeholders.add("?"));

        List<Object> params = new ArrayList<>(1 + group.scopes().size());
        params.add(group.name());
        params.addAll(group.scopes());

        this.update(this.preparedStatementList(
                """
                        DELETE `entity_scope` FROM `cnet_security_entity_scopes` `entity_scope`
                        JOIN `cnet_security_scopes` `scope` ON `scope`.`id` = `entity_scope`.`scope_id`
                        WHERE `entity_scope`.`group_id` = ?
                        AND `scope`.`value` NOT IN (%s);
                        """.formatted(placeholders),
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
                "SELECT `name` FROM `cnet_security_groups`;"
        ), "name", String.class);
    }

}
