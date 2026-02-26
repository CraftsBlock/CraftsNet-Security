package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
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

abstract sealed class AbstractFileStoreDriver implements AutoCloseable
        permits FileTokenStoreDriver {

    public static final int WARN_AT_FILE_SIZE = 1024 * 1024 * 15;

    final @NotNull Path file;
    final @NotNull Path directory;
    private final AtomicReference<Json> json = new AtomicReference<>();

    private final @NotNull FileDriverHotReloadManager hotReloadManager;
    private boolean closed = false;

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

    protected void json(Consumer<Json> consumer) {
        ensureOpen();

        synchronized (this.json) {
            consumer.accept(this.json.get());
        }
    }

    protected <R> R json(Function<Json, R> function) {
        ensureOpen();

        synchronized (this.json) {
            return function.apply(this.json.get());
        }
    }

    public void reload() {
        ensureOpen();
        synchronized (this.json) {
            this.json.set(JsonParser.parse(file));
        }
    }

    public void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("No operations allowed after closure!");
        }
    }

    @Override
    public void close() {
        ensureOpen();
        try {
            this.hotReloadManager.close();
            this.json.set(null);
        } finally {
            this.closed = true;
        }
    }

    public @NotNull Path getFile() {
        return file;
    }

    public @NotNull Path getDirectory() {
        return directory;
    }

    public boolean isClosed() {
        return closed;
    }


}
