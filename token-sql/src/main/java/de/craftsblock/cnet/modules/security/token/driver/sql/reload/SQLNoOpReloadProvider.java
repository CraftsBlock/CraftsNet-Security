package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.token.driver.sql.SQLStoreDriver;
import org.jetbrains.annotations.NotNull;

/**
 * Reload provider implementation that performs no synchronization logic.
 * <p>
 * This provider is useful when external cache invalidation or reload
 * handling is managed elsewhere and no automatic database synchronization
 * should occur.
 * <p>
 * The provider intentionally avoids closing the shared SQL connection
 * during shutdown.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class SQLNoOpReloadProvider extends SQLReloadProvider {

    /**
     * Creates a new no-operation reload provider.
     *
     * @param driver The SQL store driver associated with this provider
     */
    public SQLNoOpReloadProvider(@NotNull SQLStoreDriver driver) {
        super(driver);
    }

    /**
     * Performs no shutdown operation.
     * <p>
     * This method intentionally does nothing to avoid closing the
     * underlying SQL connection managed externally.
     */
    @Override
    public void close() {
        // Do nothing to not close the sql connection
    }
}
