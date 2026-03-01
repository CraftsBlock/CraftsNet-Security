package de.craftsblock.cnet.modules.security.token.driver;

public interface StoreDriver
        extends AutoCloseable, GroupStoreDriver, TokenStoreDriver {

    @Override
    void close();

    default void reload() {
        GroupStoreDriver.super.reload();
        TokenStoreDriver.super.reload();
    }

    default GroupStoreDriver getGroupStoreDriver() {
        return this;
    }

    default TokenStoreDriver getTokenStoreDriver() {
        return this;
    }

}
