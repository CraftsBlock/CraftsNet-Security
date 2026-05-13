package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.file.FileDriverHotReloadManager;
import de.craftsblock.cnet.modules.security.token.driver.file.FileGroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.file.FileTokenStoreDriver;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Base implementation for file-based store drivers used by the security module.
 * <p>
 * This class provides common functionality for reading, writing, and caching JSON-based
 * storage files used by {@link FileGroupStoreDriver} and {@link FileTokenStoreDriver}.
 * It also integrates a hot-reload mechanism to keep the in-memory representation
 * synchronized with the underlying file system.
 * <p>
 * Implementations are responsible for defining how the JSON structure is interpreted
 * for specific domain objects (tokens, groups, etc.).
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
abstract sealed class AbstractFileStoreDriver implements AutoCloseable
        permits FileGroupStoreDriver, FileTokenStoreDriver {

    /**
     * Warning threshold for file size in bytes (15 MB).
     * <p>
     * If a storage file exceeds this size, a warning will be logged
     * because large JSON files may negatively impact performance.
     */
    public static final int WARN_AT_FILE_SIZE = 1024 * 1024 * 15;

    final @NotNull Path file;
    final @NotNull Path directory;
    private final AtomicReference<Json> json = new AtomicReference<>();

    private final @NotNull FileDriverHotReloadManager hotReloadManager;
    private boolean closed = false;

    /**
     * Creates a new file-based store driver for the given file path.
     * <p>
     * This constructor ensures that the file and its parent directory exist,
     * initializes the JSON cache, and starts the hot-reload manager.
     *
     * @param file The file used for persistent storage.
     * @throws UncheckedIOException If the file cannot be created or read.
     */
    public AbstractFileStoreDriver(Path file) {
        this.file = file;
        this.directory = file.toAbsolutePath().getParent();

        try {
            if (Files.notExists(directory)) {
                Files.createDirectories(directory);
            }

            if (Files.notExists(file)) {
                Files.createFile(file);
            }

            long size = Files.size(file);
            if (size >= WARN_AT_FILE_SIZE) {
                Logger logger = CraftsNetSecurity.getInstance().getLogger();
                logger.warning(
                        "The store (%s) is larger than %s MB (%s MB), which may cause slowdowns!",
                        file, WARN_AT_FILE_SIZE / 1024 / 1024, size / 1024 / 1024
                );
                logger.warning("Please consider using a database.");
            }

            this.reload();
            this.hotReloadManager = new FileDriverHotReloadManager(this);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file: " + e.getMessage(), e);
        }
    }

    /**
     * Executes a consumer operation on the cached JSON data in a thread-safe manner.
     *
     * @param consumer The operation to perform on the JSON object.
     */
    protected void json(Consumer<Json> consumer) {
        ensureOpen();

        synchronized (this.json) {
            consumer.accept(this.json.get());
        }
    }

    /**
     * Applies a function to the cached JSON data and returns a result in a thread-safe manner.
     *
     * @param function The function to apply to the JSON object.
     * @param <R>      The return type of the function.
     * @return The result of applying the function to the JSON data.
     */
    protected <R> R json(Function<Json, R> function) {
        ensureOpen();

        synchronized (this.json) {
            return function.apply(this.json.get());
        }
    }

    /**
     * Reloads the underlying JSON file into memory.
     * <p>
     * This operation replaces the current cached JSON representation with
     * a freshly parsed version from disk.
     */
    public void reload() {
        ensureOpen();

        synchronized (this.json) {
            this.json.set(JsonParser.parse(file));
        }
    }

    /**
     * Ensures that this driver is still open before performing any operation.
     *
     * @throws IllegalStateException If the driver has already been closed.
     */
    public void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("No operations allowed after closure!");
        }
    }

    /**
     * Closes this store driver and releases all associated resources.
     * <p>
     * After calling this method, the instance can no longer be used.
     */
    @Override
    public void close() {
        try {
            if (!hotReloadManager.isClosed()) {
                this.hotReloadManager.close();
            }

            this.json.set(null);
        } finally {
            this.closed = true;
        }
    }

    /**
     * Returns the underlying storage file path.
     *
     * @return The file used for persistence.
     */
    public @NotNull Path getFile() {
        return file;
    }

    /**
     * Returns the directory containing the storage file.
     *
     * @return The parent directory of the storage file.
     */
    public @NotNull Path getDirectory() {
        return directory;
    }

    /**
     * Checks whether this driver has already been closed.
     *
     * @return {@code true} if the driver is closed, otherwise {@code false}.
     */
    public boolean isClosed() {
        return closed;
    }


}
