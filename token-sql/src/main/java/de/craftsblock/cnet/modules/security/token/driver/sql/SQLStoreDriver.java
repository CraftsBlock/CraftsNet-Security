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

public class SQLStoreDriver extends WrappedStoreDriver<SQLGroupStoreDriver, SQLTokenStoreDriver> {

    private final @NotNull Supplier<Connection> connectionSupplier;
    private final @NotNull SQLReloadProvider sqlReloadProvider;

    private final @NotNull SQLScopeDriver scopeDriver;
    private final @NotNull SQLSchemaUpdater schemaUpdater;

    private boolean closed;

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

    public boolean isClosed() {
        return closed;
    }

    public @NotNull Supplier<@Nullable Connection> getConnectionSupplier() {
        return connectionSupplier;
    }

    @Override
    public SQLGroupStoreDriver getGroupStoreDriver() {
        return super.getGroupStoreDriver();
    }

    @NotNull SQLScopeDriver getScopeDriver() {
        return scopeDriver;
    }

    @Override
    public SQLTokenStoreDriver getTokenStoreDriver() {
        return super.getTokenStoreDriver();
    }

    public @NotNull SQLSchemaUpdater getSchemaUpdater() {
        return schemaUpdater;
    }

    public @NotNull SQLReloadProvider getSqlReloadProvider() {
        return sqlReloadProvider;
    }

    public static SQLStoreDriver create(@NotNull Supplier<@NotNull Connection> connectionSupplier) {
        return create(connectionSupplier, SQLPollingReloadProvider::new);
    }

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
