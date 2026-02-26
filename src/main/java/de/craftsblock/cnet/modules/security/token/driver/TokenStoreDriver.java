package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.event.TokenDeleteEvent;
import de.craftsblock.cnet.modules.security.token.event.TokenPersistEvent;

import java.util.Collection;

public non-sealed interface TokenStoreDriver extends AutoCloseable, Driver {

    @Override
    default void reload() {
        CraftsNetSecurity.getTokenManager().clearCache();
    }

    boolean exists(long id);

    Token load(long id);

    default void save(Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenPersistEvent(token));
    }

    default void delete(long id) {
        this.delete(load(id));
    }

    default void delete(Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenDeleteEvent(token));
    }

    Collection<Long> getAllTokenIds();

    @Override
    void close();

}
