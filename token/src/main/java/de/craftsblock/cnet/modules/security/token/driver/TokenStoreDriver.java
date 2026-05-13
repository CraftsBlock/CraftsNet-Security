package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.TokenManager;
import de.craftsblock.cnet.modules.security.token.event.TokenDeleteEvent;
import de.craftsblock.cnet.modules.security.token.event.TokenPersistEvent;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.util.Collection;

/**
 * Persistence driver responsible for storing and managing {@link Token} entities.
 * <p>
 * Implementations of this interface define how tokens are persisted, retrieved,
 * and deleted from a storage backend such as SQL databases, file systems,
 * or in-memory repositories.
 * <p>
 * This driver also integrates with the CraftsNet event system to emit lifecycle
 * events whenever tokens are persisted or deleted.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public non-sealed interface TokenStoreDriver extends Driver {

    /**
     * Reloads the token cache managed by the {@link TokenManager}.
     * <p>
     * This is typically used when the underlying storage has changed and
     * the in-memory cache must be invalidated to ensure consistency.
     */
    default void reload() {
        TokenManager.getInstance().clearCache();
    }

    /**
     * Checks whether a token with the given identifier exists in storage.
     *
     * @param id The unique token identifier.
     * @return {@code true} if the token exists, otherwise {@code false}.
     */
    boolean existsToken(@Range(from = 0, to = Long.MAX_VALUE) long id);

    /**
     * Loads a token from the underlying storage.
     *
     * @param id The unique token identifier.
     * @return The loaded {@link Token}.
     */
    Token loadToken(@Range(from = 0, to = Long.MAX_VALUE) long id);

    /**
     * Persists the given token to the underlying storage.
     * <p>
     * This default implementation emits a {@link TokenPersistEvent}
     * but does not perform actual persistence logic, which must be
     * implemented by concrete drivers if required.
     *
     * @param token The token to persist.
     */
    default void saveToken(@NotNull Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenPersistEvent(token));
    }

    /**
     * Deletes a token by its identifier from the underlying storage.
     *
     * @param id The identifier of the token to delete.
     */
    default void deleteToken(@Range(from = 0, to = Long.MAX_VALUE) long id) {
        this.deleteToken(loadToken(id));
    }

    /**
     * Deletes the given token from the underlying storage.
     *
     * @param token The token to delete.
     */
    default void deleteToken(@NotNull Token token) {
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenDeleteEvent(token));
    }

    /**
     * Returns all token identifiers stored in the backend.
     *
     * @return A collection of all token IDs.
     */
    @NotNull Collection<Long> getAllTokenIds();

}
