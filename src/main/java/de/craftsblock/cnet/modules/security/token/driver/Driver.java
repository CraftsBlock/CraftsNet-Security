package de.craftsblock.cnet.modules.security.token.driver;

sealed interface Driver extends AutoCloseable
        permits GroupStoreDriver, TokenStoreDriver {

    @Override
    void close();

}
