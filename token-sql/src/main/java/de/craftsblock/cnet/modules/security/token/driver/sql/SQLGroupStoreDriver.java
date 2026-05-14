package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.Group;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.sql.ResultSet;
import java.util.*;
import java.util.function.Supplier;

/**
 * SQL-backed implementation of {@link GroupStoreDriver}.
 * <p>
 * This driver persists and loads token groups from a relational database.
 * Groups are stored in the {@code cnet_security_groups} table while their
 * associated scopes are managed through relational mapping tables.
 * <p>
 * Scope persistence and cleanup are delegated to the associated
 * {@link SQLScopeDriver} provided by the owning {@link SQLStoreDriver}.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see GroupStoreDriver
 * @see SQLStoreDriver
 * @since 1.0.0
 */
public final class SQLGroupStoreDriver extends AbstractSQLStoreDriver implements GroupStoreDriver {

    private SQLStoreDriver storeDriver;

    /**
     * Creates a new SQL group store driver.
     *
     * @param connectionSupplier Supplier providing JDBC connections
     */
    SQLGroupStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    /**
     * Assigns the owning {@link SQLStoreDriver} instance to this driver.
     * <p>
     * The store driver is only assigned once and subsequent calls are ignored.
     * It is required for resolving and cleaning up scope relations.
     *
     * @param storeDriver The owning SQL store driver
     */
    void setStoreDriver(@NotNull SQLStoreDriver storeDriver) {
        if (this.storeDriver != null) {
            return;
        }

        this.storeDriver = storeDriver;
    }

    /**
     * {@inheritDoc}
     *
     * @param name {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean existsGroup(@NotNull String name) {
        ensureOpen();

        return this.query(this.preparedStatement(
                "SELECT 1 FROM `cnet_security_groups` WHERE `name` = ? LIMIT 1;", name
        ), ResultSet::next);
    }

    /**
     * {@inheritDoc}
     *
     * @param name {@inheritDoc}
     * @return {@inheritDoc}
     */
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

    /**
     * {@inheritDoc}
     *
     * @param group {@inheritDoc}
     */
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

    /**
     * Persists all scopes associated with the given group and creates
     * the required relational mappings.
     *
     * @param group The group whose scopes should be persisted
     */
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

    /**
     * Removes outdated scope mappings from the database.
     * <p>
     * Any scope relation that is currently stored for the group but is no longer
     * part of the group's active scope collection will be deleted.
     *
     * @param group The group whose obsolete scope mappings should be removed
     */
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

    /**
     * {@inheritDoc}
     *
     * @param group {@inheritDoc}
     */
    @Override
    public void deleteGroup(@NotNull Group group) {
        ensureOpen();
        this.update(this.preparedStatement(
                "DELETE FROM `cnet_security_groups` WHERE `name`=?;",
                group
        ));

        this.storeDriver.getScopeDriver().cleanUpScopes();
    }

    /**
     * {@inheritDoc}
     *
     * @return {@inheritDoc}
     */
    @Override
    public @NotNull Collection<String> getAllGroupNames() {
        ensureOpen();
        return this.queryCollection(this.preparedStatement(
                "SELECT `name` FROM `cnet_security_groups`;"
        ), "name", String.class);
    }

}
