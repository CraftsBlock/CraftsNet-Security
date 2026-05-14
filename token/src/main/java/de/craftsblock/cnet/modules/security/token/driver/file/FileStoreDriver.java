package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.token.driver.WrappedStoreDriver;

import java.nio.file.Path;

/**
 * File-based implementation of a unified {@link WrappedStoreDriver}.
 * <p>
 * This driver combines {@link FileGroupStoreDriver} and {@link FileTokenStoreDriver}
 * into a single store driver instance backed by two separate JSON files.
 * <p>
 * It is primarily used when a lightweight file-based persistence layer is desired
 * instead of a database-backed implementation.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see FileGroupStoreDriver
 * @see FileTokenStoreDriver
 * @since 1.0.0
 */
public final class FileStoreDriver extends WrappedStoreDriver<FileGroupStoreDriver, FileTokenStoreDriver> {

    /**
     * Creates a new file store driver using the provided group and token drivers.
     *
     * @param groupStoreDriver The file-based group store driver.
     * @param tokenStoreDriver The file-based token store driver.
     */
    FileStoreDriver(FileGroupStoreDriver groupStoreDriver, FileTokenStoreDriver tokenStoreDriver) {
        super(groupStoreDriver, tokenStoreDriver);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the underlying file-based group store driver.
     */
    @Override
    public FileGroupStoreDriver getGroupStoreDriver() {
        return super.getGroupStoreDriver();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns the underlying file-based token store driver.
     */
    @Override
    public FileTokenStoreDriver getTokenStoreDriver() {
        return super.getTokenStoreDriver();
    }

    /**
     * Creates a new {@link FileStoreDriver} using separate JSON files
     * for groups and tokens.
     *
     * @param groupsFile The file used for storing group data.
     * @param tokensFile The file used for storing token data.
     * @return A fully initialized file store driver.
     */
    public static FileStoreDriver create(Path groupsFile, Path tokensFile) {
        return new FileStoreDriver(
                new FileGroupStoreDriver(groupsFile),
                new FileTokenStoreDriver(tokensFile)
        );
    }

}
