package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;

sealed interface Driver extends AutoCloseable
        permits GroupStoreDriver, TokenStoreDriver {

    @Override
    void close();

}
