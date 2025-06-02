package de.craftsblock.cnet.modules.security.auth.token.driver.storage;

import de.craftsblock.cnet.modules.security.auth.token.Token;

import java.util.Collection;

/**
 * Abstract base class representing a storage driver for authentication tokens.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @see Token
 * @since 1.0.0-SNAPSHOT
 */
public abstract class TokenStorageDriver {

    /**
     * Persists the given collection of tokens to the underlying storage mechanism.
     *
     * @param tokens A collection of {@link Token} instances to be saved.
     */
    public abstract void save(Collection<Token> tokens);

    /**
     * Loads all tokens currently stored in the underlying storage.
     *
     * @return A collection of all {@link Token} instances retrieved from storage.
     */
    public abstract Collection<Token> loadAll();

    /**
     * Deletes the specified token from the storage.
     * <p>
     * This is a convenience method that delegates to {@link #delete(long)} using the tokens id.
     * </p>
     *
     * @param token The {@link Token} instance to be deleted.
     */
    public void delete(Token token) {
        this.delete(token.id());
    }

    /**
     * Deletes a token identified by its unique id.
     *
     * @param id the unique identifier of the token to delete.
     */
    public void delete(long id) {
    }

}
