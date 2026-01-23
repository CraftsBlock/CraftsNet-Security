package de.craftsblock.cnet.modules.security.token.driver;

import de.craftsblock.cnet.modules.security.token.Token;

import java.util.Collection;

public interface TokenStoreDriver extends AutoCloseable {

    boolean exists(long id);

    Token load(long id);

    void save(Token token);

    default void delete(Token token) {
        this.delete(token.id());
    }

    void delete(long id);

    Collection<Long> getAllTokenIds();

    @Override
    void close();

}
