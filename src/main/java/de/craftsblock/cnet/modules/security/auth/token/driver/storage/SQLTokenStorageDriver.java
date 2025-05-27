package de.craftsblock.cnet.modules.security.auth.token.driver.storage;

import de.craftsblock.cnet.modules.security.auth.token.Token;
import de.craftsblock.cnet.modules.security.auth.token.TokenPermission;
import de.craftsblock.craftscore.sql.SQL;
import de.craftsblock.craftsnet.api.http.HttpMethod;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 * A concrete implementation of {@link TokenStorageDriver} that persists and retrieves tokens
 * and their associated permissions using an SQL-based relational database.
 *
 * <p>This class creates the required database tables, views, and triggers if they do not already exist.</p>
 * <p>It supports saving, deleting, and loading tokens, including managing the many-to-many relationship
 * between tokens and permissions.</p>
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @see SQL
 * @see TokenStorageDriver
 * @since 1.0.0-SNAPSHOT
 */
public class SQLTokenStorageDriver extends TokenStorageDriver {

    private final SQL sql;

    /**
     * Constructs a new {@link SQLTokenStorageDriver} with the given {@link SQL} connection.
     *
     * @param sql An active {@link SQL} connection to a relational database.
     * @throws IllegalStateException If the SQL connection is not active.
     */
    public SQLTokenStorageDriver(SQL sql) {
        this.sql = sql;

        try {
            if (!this.sql.isConnected())
                throw new IllegalStateException("The sql instance must be connected to the database!");
        } catch (SQLException e) {
            throw new RuntimeException("Could not verify sql connection status!", e);
        }

        // Create tables if they not exists
        this.createTables();
    }

    /**
     * Saves a collection of tokens to the database by calling {@link #save(Token)} for each token.
     *
     * @param tokens The collection of {@link Token} instances to persist.
     */
    @Override
    public void save(Collection<Token> tokens) {
        tokens.forEach(this::save);
    }

    /**
     * Saves a single token and its associated permissions to the database.
     * <p>
     * This involves:
     * <ul>
     *     <li>Inserting or updating the token in the {@code cnet_security_tokens} table</li>
     *     <li>Inserting or updating each permission in the {@code cnet_security_permissions} table</li>
     *     <li>Linking the token to its permissions in the {@code cnet_security_token_permissions} table</li>
     * </ul>
     *
     * @param token The {@link Token} to persist.
     */
    public void save(Token token) {
        try (PreparedStatement statement = this.sql.prepareStatement(
                "INSERT INTO `cnet_security_tokens` (`id`, `hash`) VALUES (?,?) ON DUPLICATE KEY UPDATE `hash`=?;"
        )) {
            statement.setLong(1, token.id());
            statement.setString(2, token.hash());
            statement.setString(3, token.hash());

            this.sql.update(statement);
        } catch (SQLException e) {
            throw new RuntimeException("Could not save token %s to the database!".formatted(token.id()), e);
        }

        List<Long> permissionIDs = new ArrayList<>();
        token.permissions().forEach(permission -> {
            try (PreparedStatement statement = this.sql.prepareStatement(
                    "INSERT INTO `cnet_security_permissions` (`id`, `path`, `domain`, `http_methods`) VALUES (?, ?, ?, ?) " +
                            "ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id);", true
            )) {
                statement.setLong(1, permission.id());
                statement.setString(2, permission.path());
                statement.setString(3, permission.domain());
                statement.setString(4, HttpMethod.asString(permission.methods()));

                statement.executeUpdate();

                try (ResultSet keys = statement.getGeneratedKeys()) {
                    if (keys.next())
                        permissionIDs.add(keys.getLong(1));
                    else permissionIDs.add(permission.id());
                }
            } catch (SQLException e) {
                throw new RuntimeException("Could not create token permission for token %s!".formatted(token.id()), e);
            }
        });

        permissionIDs.forEach(id -> {
            try (PreparedStatement statement = this.sql.prepareStatement(
                    "INSERT INTO `cnet_security_token_permissions` (`token`, `permission`) VALUES (?,?);"
            )) {
                statement.setLong(1, token.id());
                statement.setLong(2, id);
            } catch (SQLException e) {
                throw new RuntimeException("Could not link token permission %s with token %s!".formatted(id, token.id()), e);
            }
        });
    }

    /**
     * Deletes a token with the specified id from the database.
     * <p>
     * Related entries in the {@code cnet_security_token_permissions} table will also be removed,
     * and a cleanup trigger may delete unused permissions.
     *
     * @param id The ID of the token to delete.
     */
    @Override
    public void delete(long id) {
        try (PreparedStatement statement = this.sql.prepareStatement(
                "DELETE FROM `cnet_security_tokens` WHERE `cnet_security_tokens`.`id`=?;"
        )) {
            statement.setLong(1, id);
            this.sql.update(statement);
        } catch (SQLException e) {
            throw new RuntimeException("Could not delete token %s from the database!".formatted(id), e);
        }
    }

    /**
     * Loads all tokens and their associated permissions from the database.
     *
     * @return A collection of {@link Token} instances with their full permission sets.
     */
    @Override
    public Collection<Token> loadAll() {
        try (ResultSet result = this.sql.query("SELECT * FROM `cnet_security_tokens_merged`;")) {
            return createTokensFromResultSet(result).values();
        } catch (SQLException e) {
            throw new RuntimeException("Could not load all tokens in the database!", e);
        }
    }

    /**
     * Constructs tokens and their permissions from the result set of the merged view.
     *
     * @param result The {@link ResultSet} containing joined token and permission data.
     * @return A map of token ID to {@link Token} instance.
     */
    private Map<Long, Token> createTokensFromResultSet(ResultSet result) {
        Map<Long, Token> tokens = new HashMap<>();

        try {
            while (result.next()) {
                long id = result.getLong("token_id");
                String hash = result.getString("hash");

                Token token = tokens.computeIfAbsent(id, tokenID -> Token.of(tokenID, hash, new ArrayList<>()));
                token.permissions().add(createTokenPermissionFromResultSet(result));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not read token from database!", e);
        }

        return tokens;
    }

    /**
     * Creates a {@link TokenPermission} object from the current row of the result set.
     *
     * @param result The {@link ResultSet} to extract permission data from.
     * @return The constructed {@link TokenPermission}.
     */
    private TokenPermission createTokenPermissionFromResultSet(ResultSet result) {
        try {
            HttpMethod[] methods = Arrays.stream(result.getString("http_methods").split("\\|"))
                    .map(HttpMethod::parse)
                    .toArray(HttpMethod[]::new);

            return TokenPermission.of(result.getLong("permission_id"),
                    result.getString("path"), result.getString("domain"),
                    methods
            );
        } catch (SQLException e) {
            throw new RuntimeException("Could not read token permission from database!", e);
        }
    }

    /**
     * Initializes the database schema including required tables, views, and triggers
     * for managing tokens and their permissions.
     */
    private void createTables() {
        this.sqlCreate("table cnet_security_tokens", """
                CREATE TABLE IF NOT EXISTS `cnet_security_tokens` (
                	`id` BIGINT NOT NULL ,
                	`hash` VARCHAR(128) NOT NULL ,
                	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
                	`updated_at` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
                	PRIMARY KEY (`id`)
                );
                """);

        this.sqlCreate("table cnet_security_permissions", """
                CREATE TABLE IF NOT EXISTS `cnet_security_permissions` (
                	`id` BIGINT NOT NULL ,
                	`path` VARCHAR(256) NOT NULL ,
                	`domain` VARCHAR(256) NOT NULL ,
                	`http_methods` VARCHAR(128) NOT NULL ,
                	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
                	`updated_at` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
                	PRIMARY KEY (`id`)
                );
                """);

        this.sqlCreate("table cnet_security_token_permissions", """
                CREATE TABLE IF NOT EXISTS `cnet_security_token_permissions` (
                	`token` BIGINT NOT NULL ,
                	`permission` BIGINT NOT NULL ,
                	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
                	`updated_at` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
                	PRIMARY KEY(`token`, `permission`) ,
                	FOREIGN KEY (`token`) REFERENCES `cnet_security_tokens`(`id`) ON DELETE CASCADE ON UPDATE CASCADE ,
                	FOREIGN KEY (`permission`) REFERENCES `cnet_security_permissions`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE
                );
                """);

        this.sqlCreate("view cnet_security_tokens_merged", """
                CREATE OR REPLACE VIEW `cnet_security_tokens_merged` AS SELECT
                	`cnet_security_tokens`.`id` AS `token_id` ,
                	`cnet_security_tokens`.`hash` ,
                	`cnet_security_permissions`.`id` AS `permission_id` ,
                	`cnet_security_permissions`.`path` ,
                	`cnet_security_permissions`.`domain` ,
                	`cnet_security_permissions`.`http_methods`
                FROM `cnet_security_tokens`
                JOIN `cnet_security_token_permissions` ON (`cnet_security_tokens`.`id` = `cnet_security_token_permissions`.`token`)
                JOIN `cnet_security_permissions` ON (`cnet_security_token_permissions`.`permission` = `cnet_security_permissions`.`id`)
                """);

        this.sqlCreate("trigger cnet_security_cleanup_unused_permissions", """
                DELIMITER $$
                \s
                CREATE OR REPLACE TRIGGER `cnet_security_cleanup_unused_permissions`
                AFTER DELETE ON `cnet_security_token_permissions`
                FOR EACH ROW
                BEGIN
                    DECLARE remaining INT;
                \s
                    SELECT COUNT(*) INTO remaining
                    FROM `cnet_security_token_permissions`
                    WHERE `cnet_security_token_permissions`.`permission` = OLD.`permission`;
                \s
                    IF remaining = 0 THEN
                        DELETE FROM `cnet_security_permissions`
                        WHERE `cnet_security_permissions`.`id` = OLD.`permission`;
                    END IF;
                END$$
                \s
                DELIMITER ;
                """);
    }

    /**
     * Executes an SQL update for the given schema object creation command.
     *
     * @param target     A descriptive name for the target being created.
     * @param sqlCommand The SQL DDL command to execute.
     */
    private void sqlCreate(String target, String sqlCommand) {
        try {
            this.sql.update(sqlCommand);
        } catch (SQLException e) {
            throw new RuntimeException("Could not create %s!".formatted(target), e);
        }
    }

}
