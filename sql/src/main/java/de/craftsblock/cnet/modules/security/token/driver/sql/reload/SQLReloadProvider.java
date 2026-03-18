package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.token.driver.sql.SQLStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.sql.SQLWorker;
import org.jetbrains.annotations.NotNull;

public abstract class SQLReloadProvider extends SQLWorker {

    private final @NotNull SQLStoreDriver driver;

    public SQLReloadProvider(@NotNull SQLStoreDriver driver) {
        super(driver.getConnectionSupplier());
        this.driver = driver;
    }

    public @NotNull SQLStoreDriver getDriver() {
        return driver;
    }

}
