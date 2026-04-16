package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.token.driver.sql.SQLStoreDriver;
import org.jetbrains.annotations.NotNull;

public class SQLNoOpReloadProvider extends SQLReloadProvider {

    public SQLNoOpReloadProvider(@NotNull SQLStoreDriver driver) {
        super(driver);
    }

    @Override
    public void close() {
        // Do nothing to not close the sql connection
    }
}
