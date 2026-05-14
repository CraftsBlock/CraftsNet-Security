package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftsnet.utils.reflection.TypeUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.*;

/**
 * Background watcher responsible for automatically reloading file-based
 * store drivers when their underlying storage file changes.
 * <p>
 * This component uses the Java {@link WatchService} API to monitor file system
 * events and triggers a reload on the associated {@link AbstractFileStoreDriver}
 * whenever a modification of the target file is detected.
 * <p>
 * The watcher runs on a dedicated thread and is automatically started upon
 * instantiation.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
class FileDriverHotReloadManager extends Thread implements AutoCloseable {

    private final @NotNull AbstractFileStoreDriver driver;
    private final @NotNull WatchService watchService;

    private boolean closed = false;

    /**
     * Creates and starts a new hot reload manager for the given file driver.
     *
     * @param driver The file store driver to monitor for changes
     * @throws UncheckedIOException If the watch service cannot be initialized
     *                              or the directory cannot be registered
     */
    public FileDriverHotReloadManager(@NotNull AbstractFileStoreDriver driver) {
        super("Token file watcher");
        try {
            this.driver = driver;
            this.watchService = FileSystems.getDefault().newWatchService();
            driver.getDirectory().register(this.watchService, StandardWatchEventKinds.ENTRY_MODIFY);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create: " + getClass().getSimpleName(), e);
        }

        this.start();
    }

    /**
     * Continuously listens for file system events and triggers a reload
     * if the monitored file has been modified.
     * <p>
     * This loop runs until the watch service is closed or the thread is interrupted.
     */
    @Override
    public void run() {
        try {
            WatchKey key;
            while ((key = watchService.take()) != null) {
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (!TypeUtils.isAssignable(Path.class, event.kind().type())) {
                        continue;
                    }

                    Path path = (Path) event.context();
                    Path realPath = driver.getDirectory().resolve(path);
                    if (realPath.equals(driver.getFile().toAbsolutePath())) {
                        CraftsNetSecurity.getInstance().getLogger().debug(
                                "Detected file system change, reloading %s file.",
                                driver.getFile().getFileName()
                        );
                        driver.reload();
                    }
                }
                key.reset();
            }
        } catch (InterruptedException | ClosedWatchServiceException ignored) {
        }
    }

    /**
     * Closes the watch service and stops the background monitoring thread.
     * <p>
     * Ensures that the thread is properly interrupted and joined before
     * marking the manager as closed.
     *
     * @throws RuntimeException If the shutdown process fails
     */
    @Override
    public void close() {
        try {
            this.watchService.close();
            this.interrupt();
            this.join();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to close: " + e.getMessage(), e);
        } finally {
            closed = true;
        }
    }

    /**
     * Indicates whether this hot reload manager has been shut down.
     *
     * @return {@code true} if the manager is closed, otherwise {@code false}
     */
    public boolean isClosed() {
        return closed;
    }

}
