package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.TokenDataContainer;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.function.Supplier;

public final class SQLTokenStoreDriver extends AbstractSQLStoreDriver implements TokenStoreDriver {

    private SQLStoreDriver storeDriver;

    SQLTokenStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    void setStoreDriver(@NotNull SQLStoreDriver storeDriver) {
        if (this.storeDriver != null) {
            return;
        }

        this.storeDriver = storeDriver;
    }

    @Override
    public boolean existsToken(long id) {
        ensureOpen();

        return this.query(this.preparedStatement(
                "SELECT 1 FROM `cnet_security_tokens` WHERE `id` = ? LIMIT 1;", id
        ), ResultSet::next);
    }

    @Override
    public Token loadToken(final long id) {
        ensureOpen();

        TokenMeta tokenMeta = this.query(this.preparedStatement(
                "SELECT `hash`, `data_container` FROM `cnet_security_tokens` WHERE `id`=?;", id
        ), result -> {
                if (!result.next()) {
                    return null;
                }

                return new TokenMeta(
                        result.getString("hash"),
                        result.getBytes("data_container")
                );
        });

        if (tokenMeta == null) {
            return null;
        }

        try {
            Collection<String> scopes = this.queryCollection(this.preparedStatement(
                    "SELECT `scope` FROM `cnet_security_token_scopes` WHERE `token_id`=?;", id
            ), "scope", String.class);

            Collection<String> groups = this.queryCollection(this.preparedStatement(
                    "SELECT `group_name` FROM `cnet_security_token_groups_view` WHERE `token_id`=?", id
            ), "group_name", String.class);

            return new Token(
                    id, tokenMeta.hash(), scopes, OptionalGroup.fromList(groups),
                    new TokenDataContainer(tokenMeta.data())
            );
        } finally {
            tokenMeta.erase();
        }
    }

    @Override
    public void saveToken(Token token) {
        ensureOpen();

        this.update(this.preparedStatement(
                """
                        INSERT INTO `cnet_security_tokens`
                            (`id`, `hash`, `data_container`)
                        VALUES (?, ?, ?)
                        ON DUPLICATE KEY UPDATE
                            `hash` = VALUES(`hash`),
                            `data_container` = VALUES(`data_container`);""",
                token.id(), token.hash(), token.tokenDataContainer().serializeToBytes()
        ));

        persistScopes(token);
        persistGroups(token);
        TokenStoreDriver.super.saveToken(token);
    }

    private void persistScopes(Token token) {
        if (token.directScopes().isEmpty()) {
            return;
        }

        Set<Long> knownScopes = new HashSet<>(this.queryCollection(this.preparedStatement(
                "SELECT `scope_id` FROM `cnet_security_entity_scopes` WHERE `token_id` = ?;",
                token.id()
        ), "scope_id", Long.class));

        Collection<Long> scopes = this.storeDriver.getScopeDriver()
                .saveScopes(token.directScopes().toArray(String[]::new))
                .values().stream()
                .filter(id -> !knownScopes.contains(id))
                .toList();

        if (scopes.isEmpty()) {
            return;
        }

        List<Object> params = new ArrayList<>(scopes.size() * 2);
        StringJoiner values = new StringJoiner(", ");

        for (Long id : scopes) {
            values.add("(?, ?)");
            params.add(id);
            params.add(token.id());
        }

        this.update(this.preparedStatementList(
                "INSERT IGNORE INTO `cnet_security_entity_scopes` (`scope_id`, `token_id`) VALUES %s "
                        .formatted(values.toString()),
                params
        ));
    }

    private void persistGroups(Token token) {
        if (token.groupNames().isEmpty()) {
            return;
        }

        List<Object> params = new ArrayList<>(token.groupNames().size() * 2);
        StringJoiner values = new StringJoiner(", ");

        for (String group : token.groupNames()) {
            values.add("(?, ?)");
            params.add(token.id());
            params.add(group);
        }

        this.update(this.preparedStatementList(
                "INSERT IGNORE INTO `cnet_security_token_groups` (`token_id`, `group_id`) VALUES %s;".formatted(
                        values.toString()
                ), params
        ));
    }

    @Override
    public void deleteToken(Token token) {
        ensureOpen();

        this.update(this.preparedStatement(
                "DELETE FROM `cnet_security_tokens` WHERE `id` = ?;",
                token.id()
        ));

        this.storeDriver.getScopeDriver().cleanUpScopes();
        TokenStoreDriver.super.deleteToken(token);
    }

    @Override
    public Collection<Long> getAllTokenIds() {
        ensureOpen();
        return this.queryCollection(this.preparedStatement(
                "SELECT * FROM `cnet_security_tokens`;"
        ), "id", Long.class);
    }

    private record TokenMeta(String hash, byte[] data) {

        public void erase() {
            PassphraseUtils.erase(data);
        }

    }

}
