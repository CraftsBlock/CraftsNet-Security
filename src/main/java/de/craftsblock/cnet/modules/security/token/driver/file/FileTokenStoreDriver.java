package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftsnet.logging.Logger;
import de.craftsblock.craftsnet.utils.reflection.TypeUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.*;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public class FileTokenStoreDriver implements TokenStoreDriver {

    public static final int WARN_AT_FILE_SIZE = 1024 * 1024 * 15;

    private final @NotNull Path tokensDirectory;
    private final @NotNull Path tokensFile;
    private final @NotNull AtomicReference<Json> tokens = new AtomicReference<>();

    private final @NotNull Thread watchThread;
    private final @NotNull WatchService watchService;

    private boolean closed = false;

    public FileTokenStoreDriver(@NotNull Path tokensFile) {
        this.tokensFile = tokensFile;
        this.tokensDirectory = tokensFile.toAbsolutePath().getParent();

        try {
            long size = Files.size(tokensFile);
            if (size >= WARN_AT_FILE_SIZE) {
                Logger logger = CraftsNetSecurity.getInstance().getLogger();
                logger.warning(
                        "The token store is larger than %s MB (%s MB), which may cause slowdowns!",
                        WARN_AT_FILE_SIZE / 1024 / 1024, size / 1024 / 1024
                );
                logger.warning("Please consider using a database.");
            }

            this.reload();
            this.watchService = FileSystems.getDefault().newWatchService();
            this.tokensDirectory.register(this.watchService, StandardWatchEventKinds.ENTRY_MODIFY);

            this.watchThread = new Thread(() -> {
                try {
                    WatchKey key;
                    while ((key = watchService.take()) != null) {
                        for (WatchEvent<?> event : key.pollEvents()) {
                            if (!TypeUtils.isAssignable(Path.class, event.kind().type())) {
                                continue;
                            }

                            Path path = (Path) event.context();
                            Path realPath = tokensDirectory.resolve(path);
                            if (realPath.equals(tokensFile.toAbsolutePath())) {
                                this.reload();
                            }
                        }
                        key.reset();
                    }
                } catch (InterruptedException ignored) {
                }
            }, "Token file watcher");
            this.watchThread.start();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read file: " + e.getMessage(), e);
        }
    }

    private void reload() {
        ensureOpen();
        synchronized (this.tokens) {
            if (this.tokens.get() != null) {
                CraftsNetSecurity.getInstance().getLogger().debug("Detected file system change, " +
                        "reloading token file.");
            }

            this.tokens.set(JsonParser.parse(tokensFile));
        }
    }

    @Override
    public boolean exists(long id) {
        ensureOpen();
        synchronized (this.tokens) {
            return this.tokens.get().contains(String.valueOf(id));
        }
    }

    @Override
    public Token load(long id) {
        ensureOpen();
        Json token;

        synchronized (this.tokens) {
            token = this.tokens.get().getJson(String.valueOf(id));
        }

        if (token == null) {
            throw new IllegalStateException("Token for id %s not found".formatted(id));
        }

        return Token.fromJson(token);
    }

    @Override
    public void save(@NotNull Token token) {
        ensureOpen();
        Json json = token.toJson();

        synchronized (this.tokens) {
            this.tokens.get().set(String.valueOf(token.id()), json);
            this.tokens.get().save(tokensFile);
        }
    }

    @Override
    public void delete(long id) {
        ensureOpen();
        synchronized (this.tokens) {
            this.tokens.get().remove(String.valueOf(id));
        }
    }

    @Override
    public Collection<Long> getAllTokenIds() {
        ensureOpen();
        Set<String> stringIds;

        synchronized (this.tokens) {
            stringIds = this.tokens.get().keySet();
        }

        return stringIds.stream()
                .map(Long::parseLong)
                .toList();
    }

    public void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("No operations allowed after closure!");
        }
    }

    @Override
    public void close() {
        try {
            this.watchThread.interrupt();
            this.watchThread.join();
        } catch (InterruptedException ignored) {
        }

        try {
            this.watchService.close();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to close: " + e.getMessage(), e);
        }

        this.tokens.set(null);
        this.closed = true;
    }

}
