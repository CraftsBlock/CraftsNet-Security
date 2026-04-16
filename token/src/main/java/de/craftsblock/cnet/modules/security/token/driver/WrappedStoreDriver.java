package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.cnet.modules.security.token.group.Group;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;

public class WrappedStoreDriver<G extends GroupStoreDriver, T extends TokenStoreDriver> implements StoreDriver {

    private final G groupStoreDriver;
    private final T tokenStoreDriver;

    public WrappedStoreDriver(G groupStoreDriver, T tokenStoreDriver) {
        this.groupStoreDriver = groupStoreDriver;
        this.tokenStoreDriver = tokenStoreDriver;
    }

    @Override
    public boolean existsGroup(@NotNull String name) {
        return this.groupStoreDriver.existsGroup(name);
    }

    @Override
    public Group loadGroup(@NotNull String name) {
        return this.groupStoreDriver.loadGroup(name);
    }

    @Override
    public void saveGroup(@NotNull Group group) {
        this.groupStoreDriver.saveGroup(group);
    }

    @Override
    public void deleteGroup(@NotNull Group group) {
        this.groupStoreDriver.deleteGroup(group);
    }

    @Override
    public @NotNull Collection<String> getAllGroupNames() {
        return this.groupStoreDriver.getAllGroupNames();
    }

    @Override
    public boolean existsToken(long id) {
        return this.tokenStoreDriver.existsToken(id);
    }

    @Override
    public Token loadToken(long id) {
        return this.tokenStoreDriver.loadToken(id);
    }

    @Override
    public void saveToken(@NotNull Token token) {
        this.tokenStoreDriver.saveToken(token);
    }

    @Override
    public void deleteToken(@NotNull Token token) {
        this.tokenStoreDriver.deleteToken(token);
    }

    @Override
    public @NotNull Collection<Long> getAllTokenIds() {
        return this.tokenStoreDriver.getAllTokenIds();
    }

    @Override
    public G getGroupStoreDriver() {
        return groupStoreDriver;
    }

    @Override
    public T getTokenStoreDriver() {
        return tokenStoreDriver;
    }

}
