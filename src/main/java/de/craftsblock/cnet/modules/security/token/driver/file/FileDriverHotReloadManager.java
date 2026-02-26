package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftsnet.utils.reflection.TypeUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.*;

class FileDriverHotReloadManager extends Thread implements AutoCloseable {

    private final @NotNull AbstractFileStoreDriver driver;
    private final @NotNull WatchService watchService;

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
                        CraftsNetSecurity.getInstance().getLogger().debug("Detected file system change, " +
                                "reloading token file.");
                        driver.reload();
                    }
                }
                key.reset();
            }
        } catch (InterruptedException ignored) {
        }
    }

    @Override
    public void close() {
        try {
            this.watchService.close();
            this.interrupt();
            this.join();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to close: " + e.getMessage(), e);
        }
    }
}
