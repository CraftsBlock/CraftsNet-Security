package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.TokenManager;
import de.craftsblock.cnet.modules.security.token.event.TokenDeleteEvent;
import de.craftsblock.cnet.modules.security.token.event.TokenPersistEvent;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.util.Collection;

public non-sealed interface TokenStoreDriver extends Driver {

    default void reload() {
        TokenManager.getInstance().clearCache();
    }

    boolean existsToken(@Range(from = 0, to = Long.MAX_VALUE) long id);

    Token loadToken(@Range(from = 0, to = Long.MAX_VALUE) long id);

    default void saveToken(@NotNull Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenPersistEvent(token));
    }

    default void deleteToken(@Range(from = 0, to = Long.MAX_VALUE) long id) {
        this.deleteToken(loadToken(id));
    }

    default void deleteToken(@NotNull Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenDeleteEvent(token));
    }

    @NotNull Collection<Long> getAllTokenIds();

}
