package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.CraftsNetSecurityToken;
import org.jetbrains.annotations.NotNull;

public interface StoreDriver
        extends AutoCloseable, GroupStoreDriver, TokenStoreDriver {

    @Override
    default void close() {
        synchronized (this) {
            getGroupStoreDriver().close();
            getTokenStoreDriver().close();
        }
    }

    default void reload() {
        synchronized (this) {
            getGroupStoreDriver().reload();
            getTokenStoreDriver().reload();
        }
    }

    default GroupStoreDriver getGroupStoreDriver() {
        return this;
    }

    default TokenStoreDriver getTokenStoreDriver() {
        return this;
    }

    static StoreDriver getInstance() {
        return CraftsNetSecurityToken.getStoreDriver();
    }

    static void setInstance(@NotNull StoreDriver storeDriver) {
        CraftsNetSecurityToken.setStoreDriver(storeDriver);
    }

}
