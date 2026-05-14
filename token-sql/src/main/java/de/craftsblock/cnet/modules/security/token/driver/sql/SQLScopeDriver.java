package de.craftsblock.cnet.modules.security.token.driver.sql;

import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.util.*;
import java.util.function.Supplier;

/**
 * Internal SQL helper responsible for persisting and managing scopes.
 * <p>
 * This driver acts as a shared utility component for token and group
 * persistence layers. It ensures that scopes are normalized and stored
 * centrally inside the {@code cnet_security_scopes} table.
 * <p>
 * This class is intended for internal use only and is managed by
 * {@link SQLStoreDriver}.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
final class SQLScopeDriver extends AbstractSQLStoreDriver {

    private SQLStoreDriver storeDriver;

    /**
     * Creates a new SQL scope driver.
     *
     * @param connectionSupplier Supplier providing JDBC connections
     */
    public SQLScopeDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    /**
     * Assigns the owning {@link SQLStoreDriver} instance to this scope driver.
     * <p>
     * The assignment only occurs once. Additional calls are ignored.
     *
     * @param storeDriver The parent SQL store driver
     */
    void setStoreDriver(@NotNull SQLStoreDriver storeDriver) {
        if (this.storeDriver != null) {
            return;
        }

        this.storeDriver = storeDriver;
    }

    /**
     * Persists the given scopes and resolves their database identifiers.
     * <p>
     * Existing scopes are reused while missing scopes are automatically inserted.
     * The returned map contains each scope string associated with its internal
     * database ID.
     *
     * @param scopes Scopes to persist or resolve
     * @return Map containing scope names mapped to their database identifiers
     */
    public Map<String, Long> saveScopes(String... scopes) {
        this.updateBatch(
                this.preparedStatement("INSERT IGNORE INTO `cnet_security_scopes` (`value`) VALUES (?);"),
                List.of(scopes),
                (statement, scope) -> statement.setString(1, scope)
        );

        return this.query(this.preparedStatementList(
                "SELECT `id`, `value` FROM `cnet_security_scopes` WHERE `value` IN (%s)".formatted(
                        String.join(",", Collections.nCopies(scopes.length, "?"))
                ), List.of(scopes)
        ), result -> {
            Map<String, Long> resultScopes = new HashMap<>();
            while (result.next()) {
                resultScopes.put(
                        result.getString("value"),
                        result.getLong("id")
                );
            }

            return resultScopes;
        });
    }

    /**
     * Removes unused scopes from the database.
     * <p>
     * A scope is considered unused if it is no longer referenced by any
     * token or group relation table.
     */
    public void cleanUpScopes() {
        Collection<String> unusedScopes = this.queryCollection(this.preparedStatement(
                """
                        SELECT `value` AS `scope`
                        FROM `cnet_security_scopes`
                        WHERE `value` NOT IN (
                            SELECT `scope` FROM `cnet_security_group_scopes`
                            UNION
                            SELECT `scope` FROM `cnet_security_token_scopes`
                        );"""
        ), "scope", String.class);

        if (unusedScopes.isEmpty()) {
            return;
        }

        this.update(this.preparedStatementList(
                "DELETE FROM `cnet_security_scopes` WHERE `value` IN (%s)".formatted(
                        String.join(",", Collections.nCopies(unusedScopes.size(), "?"))
                ), unusedScopes
        ));
    }

}
