package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.CraftsNetSecurityToken;
import org.jetbrains.annotations.NotNull;

/**
 * Unified persistence entry point for the token security module.
 * <p>
 * This interface combines both {@link GroupStoreDriver} and {@link TokenStoreDriver}
 * into a single abstraction, allowing implementations to handle all security-related
 * persistence operations in a consistent way.
 * <p>
 * It also exposes lifecycle management methods for reloading and closing underlying
 * storage resources, ensuring both group and token subsystems remain synchronized.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see GroupStoreDriver
 * @see TokenStoreDriver
 * @since 1.0.0
 */
public interface StoreDriver
        extends AutoCloseable, GroupStoreDriver, TokenStoreDriver {

    /**
     * Closes all underlying storage resources used by both group and token drivers.
     * <p>
     * This method ensures that both the group and token persistence layers are
     * properly shut down and any external resources such as database connections
     * are released safely.
     */
    @Override
    default void close() {
        synchronized (this) {
            getGroupStoreDriver().close();
            getTokenStoreDriver().close();
        }
    }

    /**
     * Reloads both group and token storage layers.
     * <p>
     * This method is typically used to refresh in-memory caches or reinitialize
     * connections after external changes to the underlying storage.
     */
    default void reload() {
        synchronized (this) {
            getGroupStoreDriver().reload();
            getTokenStoreDriver().reload();
        }
    }

    /**
     * Returns the group storage driver implementation.
     * <p>
     * By default, this returns the current instance itself, assuming it implements
     * {@link GroupStoreDriver} directly.
     *
     * @return The group store driver.
     */
    default GroupStoreDriver getGroupStoreDriver() {
        return this;
    }

    /**
     * Returns the token storage driver implementation.
     * <p>
     * By default, this returns the current instance itself, assuming it implements
     * {@link TokenStoreDriver} directly.
     *
     * @return The token store driver.
     */
    default TokenStoreDriver getTokenStoreDriver() {
        return this;
    }

    /**
     * Retrieves the globally registered {@link StoreDriver} instance.
     *
     * @return The active store driver.
     */
    static StoreDriver getInstance() {
        return CraftsNetSecurityToken.getStoreDriver();
    }

    /**
     * Registers a global {@link StoreDriver} instance.
     *
     * @param storeDriver The store driver to register.
     */
    static void setInstance(@NotNull StoreDriver storeDriver) {
        CraftsNetSecurityToken.setStoreDriver(storeDriver);
    }

}
