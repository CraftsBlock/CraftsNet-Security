package de.craftsblock.cnet.modules.security.token.driver;

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

}
