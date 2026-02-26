package de.craftsblock.cnet.modules.security.token.driver;

public sealed interface Driver
        permits GroupStoreDriver, TokenStoreDriver {

    void reload();

}
