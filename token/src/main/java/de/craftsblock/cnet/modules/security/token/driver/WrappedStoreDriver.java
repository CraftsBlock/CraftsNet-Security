package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.group.Group;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;

/**
 * A composite {@link StoreDriver} implementation that wraps a dedicated
 * {@link GroupStoreDriver} and {@link TokenStoreDriver}.
 * <p>
 * This class acts as a delegation layer, forwarding all group-related
 * operations to the provided {@code GroupStoreDriver} and all token-related
 * operations to the provided {@code TokenStoreDriver}.
 * <p>
 * It is primarily used to combine two independent persistence implementations
 * into a single unified driver without requiring them to share the same
 * concrete class.
 *
 * @param <G> The type of the wrapped {@link GroupStoreDriver}
 * @param <T> The type of the wrapped {@link TokenStoreDriver}
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see GroupStoreDriver
 * @see TokenStoreDriver
 * @since 1.0.0
 */
public class WrappedStoreDriver<G extends GroupStoreDriver, T extends TokenStoreDriver> implements StoreDriver {

    private final G groupStoreDriver;
    private final T tokenStoreDriver;

    /**
     * Creates a new wrapped store driver using the provided group and token drivers.
     *
     * @param groupStoreDriver The driver responsible for group persistence.
     * @param tokenStoreDriver The driver responsible for token persistence.
     */
    public WrappedStoreDriver(G groupStoreDriver, T tokenStoreDriver) {
        this.groupStoreDriver = groupStoreDriver;
        this.tokenStoreDriver = tokenStoreDriver;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates the existence check to the underlying {@link GroupStoreDriver}.
     *
     * @param name {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean existsGroup(@NotNull String name) {
        return this.groupStoreDriver.existsGroup(name);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates group loading to the underlying {@link GroupStoreDriver}.
     *
     * @param name {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public Group loadGroup(@NotNull String name) {
        return this.groupStoreDriver.loadGroup(name);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates group persistence to the underlying {@link GroupStoreDriver}.
     *
     * @param group {@inheritDoc}
     */
    @Override
    public void saveGroup(@NotNull Group group) {
        this.groupStoreDriver.saveGroup(group);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates group deletion to the underlying {@link GroupStoreDriver}.
     *
     * @param group {@inheritDoc}
     */
    @Override
    public void deleteGroup(@NotNull Group group) {
        this.groupStoreDriver.deleteGroup(group);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates retrieval of all group names to the underlying {@link GroupStoreDriver}.
     *
     * @return {@inheritDoc}
     */
    @Override
    public @NotNull Collection<String> getAllGroupNames() {
        return this.groupStoreDriver.getAllGroupNames();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates token existence checks to the underlying {@link TokenStoreDriver}.
     *
     * @param id {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean existsToken(long id) {
        return this.tokenStoreDriver.existsToken(id);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates token loading to the underlying {@link TokenStoreDriver}.
     *
     * @param id {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public Token loadToken(long id) {
        return this.tokenStoreDriver.loadToken(id);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates token persistence to the underlying {@link TokenStoreDriver}.
     *
     * @param token {@inheritDoc}
     */
    @Override
    public void saveToken(@NotNull Token token) {
        this.tokenStoreDriver.saveToken(token);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates token deletion to the underlying {@link TokenStoreDriver}.
     *
     * @param token {@inheritDoc}
     */
    @Override
    public void deleteToken(@NotNull Token token) {
        this.tokenStoreDriver.deleteToken(token);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates retrieval of all token IDs to the underlying {@link TokenStoreDriver}.
     *
     * @return {@inheritDoc}
     */
    @Override
    public @NotNull Collection<Long> getAllTokenIds() {
        return this.tokenStoreDriver.getAllTokenIds();
    }

    /**
     * Returns the wrapped {@link GroupStoreDriver} instance.
     *
     * @return The group store driver.
     */
    @Override
    public G getGroupStoreDriver() {
        return groupStoreDriver;
    }

    /**
     * Returns the wrapped {@link TokenStoreDriver} instance.
     *
     * @return The token store driver.
     */
    @Override
    public T getTokenStoreDriver() {
        return tokenStoreDriver;
    }

}
