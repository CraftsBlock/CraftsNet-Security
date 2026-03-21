package de.craftsblock.cnet.modules.security.token.driver.sql.util;

import java.sql.SQLException;
import java.util.function.BiConsumer;
import java.util.function.Function;

@FunctionalInterface
public interface SQLFunction<T, R> extends Function<T, R> {

    R applyThrows(T t) throws SQLException;

    @Override
    default R apply(T t) {
        try {
            return this.applyThrows(t);
        } catch (SQLException e) {
            throw new RuntimeException("There has been an sql exception!", e);
        }
    }
}
