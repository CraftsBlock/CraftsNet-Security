package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.token.driver.sql.SQLStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.sql.SQLWorker;
import org.jetbrains.annotations.NotNull;

/**
 * Base implementation for SQL-based cache reload providers.
 * <p>
 * Reload providers are responsible for detecting external changes to the
 * underlying SQL storage and triggering cache or driver reload operations
 * when required.
 * <p>
 * Implementations may use different synchronization mechanisms such as
 * polling, database notifications, or external messaging systems.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public abstract class SQLReloadProvider extends SQLWorker {

    private final @NotNull SQLStoreDriver driver;

    /**
     * Creates a new SQL reload provider.
     *
     * @param driver The SQL store driver associated with this provider
     */
    public SQLReloadProvider(@NotNull SQLStoreDriver driver) {
        super(driver.getConnectionSupplier());
        this.driver = driver;
    }

    /**
     * Returns the SQL store driver managed by this reload provider.
     *
     * @return The associated SQL store driver
     */
    public @NotNull SQLStoreDriver getDriver() {
        return driver;
    }

}
