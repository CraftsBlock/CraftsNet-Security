package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.WrappedStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.sql.reload.SQLPollingReloadProvider;
import de.craftsblock.cnet.modules.security.token.driver.sql.reload.SQLReloadProvider;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.sql.Connection;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Combined SQL-backed implementation of the token store system.
 * <p>
 * This store driver bundles the individual SQL persistence drivers for
 * groups, scopes and tokens into a single unified storage abstraction.
 * It additionally manages schema upgrades and automatic cache reload
 * synchronization through a configurable {@link SQLReloadProvider}.
 * <p>
 * During initialization, the driver validates and upgrades the database
 * schema if necessary before enabling reload synchronization.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class SQLStoreDriver extends WrappedStoreDriver<SQLGroupStoreDriver, SQLTokenStoreDriver> {

    private final @NotNull Supplier<Connection> connectionSupplier;
    private final @NotNull SQLReloadProvider sqlReloadProvider;

    private final @NotNull SQLScopeDriver scopeDriver;
    private final @NotNull SQLSchemaUpdater schemaUpdater;

    private boolean closed;

    /**
     * Creates a new SQL store driver instance.
     * <p>
     * All underlying SQL drivers are linked together and configured to use
     * the same connection supplier and reload synchronization provider.
     *
     * @param groupStoreDriver   The SQL group store driver
     * @param scopeDriver        The SQL scope persistence driver
     * @param tokenStoreDriver   The SQL token store driver
     * @param schemaUpdater      The schema updater used for migration handling
     * @param connectionSupplier Supplier used to provide SQL connections
     * @param providerFactory    Factory used to create the reload provider
     */
    SQLStoreDriver(@NotNull SQLGroupStoreDriver groupStoreDriver,
                   @NotNull SQLScopeDriver scopeDriver,
                   @NotNull SQLTokenStoreDriver tokenStoreDriver,
                   @NotNull SQLSchemaUpdater schemaUpdater,
                   @NotNull Supplier<@NotNull Connection> connectionSupplier,
                   @NotNull Function<@NotNull SQLStoreDriver, @NotNull SQLReloadProvider> providerFactory) {
        super(groupStoreDriver, tokenStoreDriver);

        // When the store driver is close no more interactions with the underlying
        // connection supplier should be made to prevent unnecessary reconnections
        this.connectionSupplier = () -> {
            if (isClosed()) {
                return null;
            }

            return connectionSupplier.get();
        };

        this.scopeDriver = scopeDriver;
        this.schemaUpdater = schemaUpdater;

        this.getGroupStoreDriver().setStoreDriver(this);
        this.scopeDriver.setStoreDriver(this);
        this.getTokenStoreDriver().setStoreDriver(this);

        Logger logger = CraftsNetSecurity.getInstance().getLogger();
        if (this.schemaUpdater.needsUpgrade()) {
            logger.debug("Needed db schema updates found");
            this.schemaUpdater.performUpgrade();
        } else {
            logger.debug("Your db schema is on the newest version %s", this.schemaUpdater.getCurrentInstalledVersion());
        }

        this.sqlReloadProvider = providerFactory.apply(this);
    }

    /**
     * Closes the store driver and all associated resources.
     * <p>
     * This includes the active reload provider and all underlying SQL
     * persistence drivers.
     *
     * @throws RuntimeException If closing the reload provider fails
     */
    @Override
    public synchronized void close() {
        try {
            sqlReloadProvider.close();
            super.close();
        } catch (Exception e) {
            throw new RuntimeException("Failed to close the sql reload provider: " + e.getMessage(), e);
        } finally {
            this.closed = true;
        }
    }

    /**
     * Returns whether this store driver has already been closed.
     *
     * @return {@code true} if the driver is closed, otherwise {@code false}
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Returns the connection supplier used by this store driver.
     * <p>
     * Once the driver is closed, the returned supplier no longer creates
     * new database connections.
     *
     * @return The managed SQL connection supplier
     */
    public @NotNull Supplier<@Nullable Connection> getConnectionSupplier() {
        return connectionSupplier;
    }

    /**
     * Returns the SQL group store driver.
     *
     * @return The group store driver instance
     */
    @Override
    public SQLGroupStoreDriver getGroupStoreDriver() {
        return super.getGroupStoreDriver();
    }

    /**
     * Returns the internal SQL scope persistence driver.
     *
     * @return The scope persistence driver
     */
    @NotNull SQLScopeDriver getScopeDriver() {
        return scopeDriver;
    }

    /**
     * Returns the SQL token store driver.
     *
     * @return The token store driver instance
     */
    @Override
    public SQLTokenStoreDriver getTokenStoreDriver() {
        return super.getTokenStoreDriver();
    }

    /**
     * Returns the schema updater used by this store driver.
     *
     * @return The schema updater
     */
    public @NotNull SQLSchemaUpdater getSchemaUpdater() {
        return schemaUpdater;
    }

    /**
     * Returns the reload provider responsible for cache synchronization.
     *
     * @return The active SQL reload provider
     */
    public @NotNull SQLReloadProvider getSqlReloadProvider() {
        return sqlReloadProvider;
    }

    /**
     * Creates a new SQL store driver using the default polling-based reload
     * provider implementation.
     *
     * @param connectionSupplier Supplier used to provide SQL connections
     * @return A newly created SQL store driver
     */
    public static SQLStoreDriver create(@NotNull Supplier<@NotNull Connection> connectionSupplier) {
        return create(connectionSupplier, SQLPollingReloadProvider::new);
    }

    /**
     * Creates a new SQL store driver using a custom reload provider factory.
     *
     * @param connectionSupplier Supplier used to provide SQL connections
     * @param providerFactory    Factory used to create the reload provider
     * @return A newly created SQL store driver
     */
    public static SQLStoreDriver create(@NotNull Supplier<@NotNull Connection> connectionSupplier,
                                        @NotNull Function<@NotNull SQLStoreDriver, @NotNull SQLReloadProvider> providerFactory) {
        return new SQLStoreDriver(
                new SQLGroupStoreDriver(connectionSupplier),
                new SQLScopeDriver(connectionSupplier),
                new SQLTokenStoreDriver(connectionSupplier),
                new SQLSchemaUpdater(connectionSupplier),
                connectionSupplier,
                providerFactory
        );
    }

}
