package de.craftsblock.cnet.modules.security.token.driver.file;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;

import java.nio.file.Path;
import java.util.Collection;
import java.util.Set;

public final class FileTokenStoreDriver extends AbstractFileStoreDriver implements TokenStoreDriver {

    public FileTokenStoreDriver(@NotNull Path tokensFile) {
        super(tokensFile);
    }

    @Override
    public void reload() {
        TokenStoreDriver.super.reload();
        super.reload();
    }

    @Override
    public boolean exists(long id) {
        return this.json(json -> {
            return json.contains(String.valueOf(id));
        });
    }

    @Override
    public Token load(long id) {
        Json token = this.json(json -> {
            return json.getJson(String.valueOf(id));
        });

        if (token == null) {
            throw new IllegalStateException("Token for id %s not found".formatted(id));
        }

        return Token.fromJson(token);
    }

    @Override
    public void save(@NotNull Token token) {
        this.json(json -> {
            json.set(String.valueOf(token.id()), token.toJson());
            json.save(file);
        });
    }

    @Override
    public void delete(Token token) {
        this.json(json -> {
            json.remove(String.valueOf(token.id()));
            json.save(file);
            TokenStoreDriver.super.delete(token);
        });
    }

    @Override
    public Collection<Long> getAllTokenIds() {
        Set<String> stringIds = this.json(json -> {
            return json.keySet();
        });

        return stringIds.stream()
                .map(Long::parseLong)
                .toList();
    }

}
