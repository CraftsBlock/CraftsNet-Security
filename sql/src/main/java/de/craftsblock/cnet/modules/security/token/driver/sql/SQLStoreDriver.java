package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.WrappedStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.util.function.Supplier;

public class SQLStoreDriver extends WrappedStoreDriver<SQLGroupStoreDriver, SQLTokenStoreDriver> {

    private final @NotNull SQLScopeDriver scopeDriver;
    private final @NotNull SQLSchemaUpdater schemaUpdater;

    SQLStoreDriver(@NotNull SQLGroupStoreDriver groupStoreDriver,
                   @NotNull SQLScopeDriver scopeDriver,
                   @NotNull SQLTokenStoreDriver tokenStoreDriver,
                   @NotNull SQLSchemaUpdater schemaUpdater) {
        super(groupStoreDriver, tokenStoreDriver);
        this.scopeDriver = scopeDriver;
        this.schemaUpdater = schemaUpdater;

        this.getGroupStoreDriver().setStoreDriver(this);
        this.scopeDriver.setStoreDriver(this);
        this.getTokenStoreDriver().setStoreDriver(this);

        Logger logger = CraftsNetSecurity.getInstance().getLogger();
        if (schemaUpdater.needsUpgrade()) {
            logger.debug("Needed db schema updates found");
            schemaUpdater.performUpgrade();
        } else {
            logger.debug("Your db schema is on the newest version %s", schemaUpdater.getCurrentInstalledVersion());
        }
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

    public static SQLStoreDriver create(Supplier<Connection> connectionSupplier) {
        return new SQLStoreDriver(
                new SQLGroupStoreDriver(connectionSupplier),
                new SQLScopeDriver(connectionSupplier),
                new SQLTokenStoreDriver(connectionSupplier),
                new SQLSchemaUpdater(connectionSupplier)
        );
    }

}
