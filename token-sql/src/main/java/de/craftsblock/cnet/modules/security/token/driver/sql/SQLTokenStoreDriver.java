package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.TokenDataContainer;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.sql.ResultSet;
import java.util.*;
import java.util.function.Supplier;

/**
 * SQL-based implementation of {@link TokenStoreDriver}.
 * <p>
 * This driver persists and loads {@link Token} instances using a relational
 * database backend. Token metadata, scopes, groups and serialized data
 * containers are distributed across multiple normalized tables.
 * <p>
 * The implementation also manages token-to-scope and token-to-group
 * relationships and integrates with {@link SQLScopeDriver} to ensure
 * consistent scope persistence and cleanup.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class SQLTokenStoreDriver extends AbstractSQLStoreDriver implements TokenStoreDriver {

    private SQLStoreDriver storeDriver;

    /**
     * Creates a new SQL token store driver.
     *
     * @param connectionSupplier Supplier used to provide SQL connections
     */
    SQLTokenStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    /**
     * Sets the owning {@link SQLStoreDriver} instance.
     * <p>
     * This reference is required to access shared SQL utilities such as the
     * {@link SQLScopeDriver}. The reference can only be assigned once.
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
     * {@inheritDoc}
     *
     * @param id {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean existsToken(long id) {
        ensureOpen();

        return this.query(this.preparedStatement(
                "SELECT 1 FROM `cnet_security_tokens` WHERE `id` = ? LIMIT 1;", id
        ), ResultSet::next);
    }

    /**
     * {@inheritDoc}
     *
     * @param id {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public Token loadToken(final long id) {
        ensureOpen();

        return this.query(this.preparedStatement(
                """
                        SELECT
                            `token`.`id`,
                            `token`.`hash`,
                            `token`.`data_container`,
                            `scope`.`value` AS `scope`,
                            `group`.`name` AS `group_name`
                        FROM `cnet_security_tokens` `token`
                        LEFT JOIN `cnet_security_entity_scopes` `entity_scope` ON `entity_scope`.`token_id` = `token`.`id`
                        LEFT JOIN `cnet_security_scopes` `scope` ON `scope`.`id` = `entity_scope`.`scope_id`
                        LEFT JOIN `cnet_security_token_groups` `token_group` ON `token_group`.`token_id` = `token`.`id`
                        LEFT JOIN `cnet_security_groups` `group` ON `group`.`name` = `token_group`.`group_id`
                        WHERE `token`.`id` = ?;
                        """,
                id
        ), result -> {
            String hash = null;
            byte[] data = null;
            boolean found = false;

            final Set<String> scopes = new HashSet<>();
            final Set<String> groups = new HashSet<>();

            while (result.next()) {
                if (!found) {
                    hash = result.getString("hash");
                    data = result.getBytes("data_container");
                    found = true;
                }

                String scope = result.getString("scope");
                if (scope != null) {
                    scopes.add(scope);
                }

                String group = result.getString("group_name");
                if (group != null) {
                    groups.add(group);
                }
            }

            if (!found) {
                return null;
            }

            return new Token(
                    id,
                    hash,
                    scopes,
                    OptionalGroup.fromList(groups),
                    new TokenDataContainer(data)
            );
        });
    }

    /**
     * {@inheritDoc}
     *
     * @param token {@inheritDoc}
     */
    @Override
    public void saveToken(@NotNull Token token) {
        ensureOpen();

        this.update(this.preparedStatement(
                """
                        INSERT INTO `cnet_security_tokens`
                            (`id`, `hash`, `data_container`)
                        VALUES (?, ?, ?)
                        ON DUPLICATE KEY UPDATE
                            `data_container` = IF(`data_container` != VALUES(`data_container`), VALUES(`data_container`), `data_container`)""",
                token.id(), token.hash(), token.tokenDataContainer().serializeToBytes()
        ));

        persistScopes(token);
        persistGroups(token);
        TokenStoreDriver.super.saveToken(token);
    }

    /**
     * Persists all directly assigned scopes of the given token.
     * <p>
     * Missing scopes are automatically created before relations are inserted
     * into the entity scope mapping table.
     *
     * @param token The token whose scopes should be persisted
     */
    private void persistScopes(Token token) {
        if (token.directScopes().isEmpty()) {
            return;
        }

        Collection<Long> scopes = this.storeDriver.getScopeDriver()
                .saveScopes(token.directScopes().toArray(String[]::new))
                .values();

        if (scopes.isEmpty()) {
            return;
        }

        final long tokenId = token.id();
        this.updateBatch(
                this.preparedStatement(
                        "INSERT IGNORE INTO `cnet_security_entity_scopes` (`scope_id`, `token_id`) VALUES (?, ?);"
                ), scopes,
                (statement, scopeId) -> {
                    statement.setLong(1, scopeId);
                    statement.setLong(2, tokenId);
                }
        );
    }

    /**
     * Persists all group relations of the given token.
     *
     * @param token The token whose groups should be linked
     */
    private void persistGroups(Token token) {
        if (token.groupNames().isEmpty()) {
            return;
        }

        final long tokenId = token.id();
        this.updateBatch(
                this.preparedStatement(
                        "INSERT IGNORE INTO `cnet_security_token_groups` (`token_id`, `group_id`) VALUES (?, ?);"
                ), token.groupNames(),
                (statement, group) -> {
                    statement.setLong(1, tokenId);
                    statement.setString(2, group);
                }
        );
    }

    /**
     * {@inheritDoc}
     *
     * @param token {@inheritDoc}
     */
    @Override
    public void deleteToken(@NotNull Token token) {
        ensureOpen();

        this.update(this.preparedStatement(
                "DELETE FROM `cnet_security_tokens` WHERE `id` = ?;",
                token.id()
        ));

        this.storeDriver.getScopeDriver().cleanUpScopes();
        TokenStoreDriver.super.deleteToken(token);
    }

    /**
     * {@inheritDoc}
     *
     * @return {@inheritDoc}
     */
    @Override
    public @NotNull Collection<Long> getAllTokenIds() {
        ensureOpen();
        return this.queryCollection(this.preparedStatement(
                "SELECT `id` FROM `cnet_security_tokens`;"
        ), "id", Long.class);
    }

}
