package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.event.TokenDeleteEvent;
import de.craftsblock.cnet.modules.security.token.event.TokenPersistEvent;

import java.util.Collection;

public non-sealed interface TokenStoreDriver extends Driver {

    default void reload() {
        CraftsNetSecurity.getTokenManager().clearCache();
    }

    boolean existsToken(long id);

    Token loadToken(long id);

    default void saveToken(Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenPersistEvent(token));
    }

    default void deleteToken(long id) {
        this.deleteToken(loadToken(id));
    }

    default void deleteToken(Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenDeleteEvent(token));
    }

    Collection<Long> getAllTokenIds();

}
