package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;

import java.nio.file.Path;
import java.util.Collection;
import java.util.Set;

/**
 * File-based implementation of the {@link TokenStoreDriver}.
 * <p>
 * This driver persists {@link Token} instances inside a JSON file where each
 * token is stored under its numeric identifier as the root key.
 * <p>
 * It extends {@link AbstractFileStoreDriver} to reuse common file handling,
 * caching, and hot-reload capabilities.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see AbstractFileStoreDriver
 * @see TokenStoreDriver
 * @since 1.0.0
 */
public final class FileTokenStoreDriver extends AbstractFileStoreDriver implements TokenStoreDriver {

    /**
     * Creates a new file-based token store driver.
     *
     * @param tokensFile The file used to persist token data.
     */
    FileTokenStoreDriver(@NotNull Path tokensFile) {
        super(tokensFile);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reload() {
        TokenStoreDriver.super.reload();
        super.reload();
    }

    /**
     * {@inheritDoc}
     *
     * @param id {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean existsToken(long id) {
        return this.json(json -> {
            return json.contains(String.valueOf(id));
        });
    }

    /**
     * {@inheritDoc}
     *
     * @param id {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public Token loadToken(long id) {
        Json token = this.json(json -> {
            return json.getJson(String.valueOf(id));
        });

        if (token == null) {
            return null;
        }

        return Token.fromJson(token);
    }

    /**
     * {@inheritDoc}
     *
     * @param token {@inheritDoc}
     */
    @Override
    public void saveToken(@NotNull Token token) {
        this.json(json -> {
            json.set(String.valueOf(token.id()), token.toJson());
            json.save(file);
            TokenStoreDriver.super.saveToken(token);
        });
    }

    /**
     * {@inheritDoc}
     *
     * @param token {@inheritDoc}
     */
    @Override
    public void deleteToken(@NotNull Token token) {
        this.json(json -> {
            json.remove(String.valueOf(token.id()));
            json.save(file);
            TokenStoreDriver.super.deleteToken(token);
        });
    }

    /**
     * {@inheritDoc}
     *
     * @return {@inheritDoc}
     */
    @Override
    public @NotNull Collection<Long> getAllTokenIds() {
        Set<String> stringIds = this.json(json -> {
            return json.keySet();
        });

        return stringIds.stream()
                .map(Long::parseLong)
                .toList();
    }

}
