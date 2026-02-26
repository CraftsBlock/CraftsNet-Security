package de.craftsblock.cnet.modules.security.token.driver;

public sealed interface Driver
        permits TokenStoreDriver {

    void reload();

}
