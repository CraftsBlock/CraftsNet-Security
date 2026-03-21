package de.craftsblock.cnet.modules.security.token.driver.sql.util;

import java.sql.SQLException;
import java.util.function.BiConsumer;

@FunctionalInterface
public interface SQLBiConsumer<T, U> extends BiConsumer<T, U> {

    void acceptThrows(T t, U u) throws SQLException;

    @Override
    default void accept(T t, U u) {
        try {
            this.acceptThrows(t, u);
        } catch (SQLException e) {
            throw new RuntimeException("There has been an sql exception!", e);
        }
    }
}
