package de.craftsblock.cnet.modules.security.token.driver.sql.schema;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.sql.SQLWorker;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgarde.SQLSchemaUpdate2026_03_09;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgarde.SQLSchemaUpdate2026_03_21;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.Contract;

import java.sql.Connection;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Handles database schema version management for the token SQL driver.
 * <p>
 * This component is responsible for determining whether schema upgrades
 * are required, executing migrations in the correct order, and tracking
 * installed schema versions inside the database.
 * <p>
 * All available schema upgrades are stored in chronological order and
 * executed sequentially when required.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see SQLSchemaUpgrade
 * @since 1.0.0
 */
public class SQLSchemaUpdater extends SQLWorker {

    /**
     * Ordered list of all available schema upgrades.
     */
    public final LinkedList<SQLSchemaUpgrade> versions;

    /**
     * Creates a new schema updater instance.
     *
     * @param connectionSupplier The supplier used to obtain SQL connections
     */
    public SQLSchemaUpdater(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
        this.versions = new LinkedList<>(List.of(
                new SQLSchemaUpdate2026_03_09(this),
                new SQLSchemaUpdate2026_03_21(this)
        ));
    }

    /**
     * Checks whether the database schema requires an upgrade.
     * <p>
     * If no schema history table exists, the schema is considered outdated
     * and installation is required.
     *
     * @return {@code true} if upgrades are pending,
     * otherwise {@code false}
     */
    public boolean needsUpgrade() {
        if (!isSchemaInstalled()) {
            return true;
        }

        String version = getCurrentInstalledVersion();
        return !versions.getLast().getVersion().equalsIgnoreCase(version);
    }

    /**
     * Executes all pending schema upgrades.
     * <p>
     * Upgrade execution starts after the currently installed version and
     * continues sequentially until the newest available version is reached.
     * Each executed migration is recorded in the schema history table.
     *
     * @throws IllegalStateException If a schema upgrade fails
     */
    public void performUpgrade() {
        Logger logger = CraftsNetSecurity.getInstance().getLogger();
        int offset;

        if (isSchemaInstalled()) {
            String currentInstalledVersion = getCurrentInstalledVersion();
            SQLSchemaUpgrade currentInstalled = getUpgrade(currentInstalledVersion);

            if (currentInstalled == null) {
                logger.error("Provided db schema is newer than any available schema updates.");
                logger.error("Are you operating two different versions of craftsnet security?");
                logger.error("Resuming with newer db schema %s, this may cause exceptions!",
                        currentInstalledVersion);
                logger.error("Consider updating to a newer version of craftsnet security!");
                return;
            }

            offset = versions.indexOf(currentInstalled);
        } else {
            offset = -1;
        }

        for (int i = offset + 1; i < versions.size(); i++) {
            SQLSchemaUpgrade update = versions.get(i);
            String version = update.getVersion();

            long start = System.currentTimeMillis();
            boolean success = update.upgrade();
            long executionTime = System.currentTimeMillis() - start;

            this.update(this.preparedStatement("""
                    INSERT INTO `cnet_security_schema_history`
                        (`version`, `execution_time`, `success`)
                    VALUES (?, ?, ?)
                    """, version, executionTime, success));

            if (!success) {
                throw new IllegalStateException("Failed to update db schema to " + version);
            } else {
                logger.debug("Installed db schema version %s after %sms",
                        version, executionTime);
            }
        }
    }

    /**
     * Resolves a schema upgrade by its version identifier.
     *
     * @param version The schema version to resolve
     * @return The matching schema upgrade, or {@code null} if none exists
     */
    @Contract("null -> null")
    public SQLSchemaUpgrade getUpgrade(String version) {
        if (version == null) {
            return null;
        }

        return versions.stream()
                .filter(upgrade -> upgrade.getVersion().equalsIgnoreCase(version))
                .findFirst()
                .orElse(null);
    }

    /**
     * Checks whether the schema history table exists.
     * <p>
     * The presence of this table indicates that schema tracking has already
     * been initialized.
     *
     * @return {@code true} if the schema history table exists,
     * otherwise {@code false}
     */
    public boolean isSchemaInstalled() {
        return this.query(this.preparedStatement("""
                SELECT COUNT(*)
                FROM `information_schema`.`tables`
                WHERE `table_schema` = DATABASE()
                  AND `table_name` = 'cnet_security_schema_history';
                """), result -> result.next() && result.getInt(1) == 1);
    }

    /**
     * Returns the latest successfully installed schema version.
     *
     * @return The installed schema version, or {@code null} if none exists
     */
    public String getCurrentInstalledVersion() {
        return this.query(this.preparedStatement("""
                SELECT `version`
                FROM `cnet_security_schema_history`
                WHERE `success` = true
                ORDER BY `id` DESC LIMIT 1;
                """), result -> result.next() ? result.getString("version") : null);
    }

}
