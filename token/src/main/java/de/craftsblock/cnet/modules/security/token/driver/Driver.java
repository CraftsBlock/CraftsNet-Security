package de.craftsblock.cnet.modules.security.token.driver;

/**
 * Base interface for all persistence drivers used by the token security module.
 * <p>
 * A driver is responsible for managing the lifecycle of persisted security-related
 * data, such as tokens or groups. Implementations define how data is stored and
 * retrieved (e.g. in-memory, SQL databases, filesystems, etc.).
 * <p>
 * All drivers must support proper resource cleanup via {@link #close()}.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
sealed interface Driver extends AutoCloseable
        permits GroupStoreDriver, TokenStoreDriver {

    /**
     * Closes the driver and releases any held resources.
     * <p>
     * This method should be used to gracefully shut down connections,
     * flush buffers, or release any external resources such as database
     * connections or file handles.
     */
    @Override
    void close();

}
