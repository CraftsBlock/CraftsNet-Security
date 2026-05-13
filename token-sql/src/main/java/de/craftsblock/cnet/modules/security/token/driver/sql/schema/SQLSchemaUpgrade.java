package de.craftsblock.cnet.modules.security.token.driver.sql.schema;

import de.craftsblock.cnet.modules.security.token.driver.sql.SQLWorker;

/**
 * Represents a single SQL schema migration step for the token SQL driver.
 * <p>
 * Schema upgrades are responsible for migrating the underlying database
 * structure between different schema versions. Each implementation contains
 * both upgrade and downgrade logic for a specific version identifier.
 * <p>
 * Upgrades are managed and executed by {@link SQLSchemaUpdater}, which keeps
 * track of installed versions and applies pending migrations in order.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see SQLSchemaUpdater
 * @since 1.0.0
 */
public abstract class SQLSchemaUpgrade extends SQLWorker {

    private final SQLSchemaUpdater updater;
    private final String version;

    /**
     * Creates a new schema upgrade definition.
     *
     * @param updater The schema updater managing this upgrade
     * @param version The version identifier represented by this upgrade
     */
    public SQLSchemaUpgrade(SQLSchemaUpdater updater, String version) {
        super(updater.getConnectionSupplier());
        this.updater = updater;
        this.version = version;
    }

    /**
     * Performs the schema upgrade.
     * <p>
     * Implementations should apply all required database changes necessary
     * to migrate to the target schema version.
     *
     * @return {@code true} if the upgrade completed successfully,
     * otherwise {@code false}
     */
    public abstract boolean upgrade();

    /**
     * Performs the schema downgrade.
     * <p>
     * Implementations should revert all changes introduced by the matching
     * {@link #upgrade()} operation.
     *
     * @return {@code true} if the downgrade completed successfully,
     * otherwise {@code false}
     */
    public abstract boolean downgrade();

    /**
     * Returns the updater responsible for managing this schema migration.
     *
     * @return The owning schema updater
     */
    public SQLSchemaUpdater getUpdater() {
        return updater;
    }

    /**
     * Returns the schema version represented by this migration.
     *
     * @return The schema version identifier
     */
    public String getVersion() {
        return version;
    }

}
