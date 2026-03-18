package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.token.driver.sql.AbstractSQLStoreDriver;
import org.jetbrains.annotations.NotNull;

public abstract class SQLReloadProvider {

    private final @NotNull AbstractSQLStoreDriver driver;

    public SQLReloadProvider(@NotNull AbstractSQLStoreDriver driver) {
        this.driver = driver;
    }

    public @NotNull AbstractSQLStoreDriver getDriver() {
        return driver;
    }

}
