package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.WrappedStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.sql.reload.SQLPollingReloadProvider;
import de.craftsblock.cnet.modules.security.token.driver.sql.reload.SQLReloadProvider;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.util.function.Function;
import java.util.function.Supplier;

public class SQLStoreDriver extends WrappedStoreDriver<SQLGroupStoreDriver, SQLTokenStoreDriver> {

    private final @NotNull SQLScopeDriver scopeDriver;
    private final @NotNull SQLSchemaUpdater schemaUpdater;

    private final @NotNull SQLReloadProvider groupSQLReloadProvider;
    private final @NotNull SQLReloadProvider tokenSQLReloadProvider;

    SQLStoreDriver(@NotNull SQLGroupStoreDriver groupStoreDriver,
                   @NotNull SQLScopeDriver scopeDriver,
                   @NotNull SQLTokenStoreDriver tokenStoreDriver,
                   @NotNull SQLSchemaUpdater schemaUpdater,
                   @NotNull Function<@NotNull AbstractSQLStoreDriver, @NotNull SQLReloadProvider> providerFactory) {
        super(groupStoreDriver, tokenStoreDriver);

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

        this.groupSQLReloadProvider = providerFactory.apply(groupStoreDriver);
        this.tokenSQLReloadProvider = providerFactory.apply(tokenStoreDriver);
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

    public @NotNull SQLReloadProvider getTokenSQLReloadProvider() {
        return tokenSQLReloadProvider;
    }

    public @NotNull SQLReloadProvider getGroupSQLReloadProvider() {
        return groupSQLReloadProvider;
    }

    public static SQLStoreDriver create(@NotNull Supplier<@NotNull Connection> connectionSupplier) {
        return create(connectionSupplier, SQLPollingReloadProvider::new);
    }

    public static SQLStoreDriver create(@NotNull Supplier<@NotNull Connection> connectionSupplier,
                                        @NotNull Function<@NotNull AbstractSQLStoreDriver, @NotNull SQLReloadProvider> providerFactory) {
        return new SQLStoreDriver(
                new SQLGroupStoreDriver(connectionSupplier),
                new SQLScopeDriver(connectionSupplier),
                new SQLTokenStoreDriver(connectionSupplier),
                new SQLSchemaUpdater(connectionSupplier),
                providerFactory
        );
    }

}
