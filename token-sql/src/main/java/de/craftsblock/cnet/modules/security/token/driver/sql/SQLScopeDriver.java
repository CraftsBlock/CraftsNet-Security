package de.craftsblock.cnet.modules.security.token.driver.sql;

import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.util.*;
import java.util.function.Supplier;

final class SQLScopeDriver extends AbstractSQLStoreDriver {

    private SQLStoreDriver storeDriver;

    public SQLScopeDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    public void setStoreDriver(@NotNull SQLStoreDriver storeDriver) {
        if (this.storeDriver != null) {
            return;
        }

        this.storeDriver = storeDriver;
    }

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
