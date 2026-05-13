package de.craftsblock.cnet.modules.security.token.driver.sql.util;

import java.sql.SQLException;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Functional SQL-aware extension of {@link Function}.
 * <p>
 * This interface allows lambda expressions and method references to throw
 * {@link SQLException}s while still being usable in contexts expecting a
 * standard {@link Function}. Checked SQL exceptions are automatically wrapped
 * into {@link RuntimeException}s by the default implementation.
 *
 * @param <T> The input type
 * @param <R> The result type
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@FunctionalInterface
public interface SQLFunction<T, R> extends Function<T, R> {

    /**
     * Applies this function and allows throwing {@link SQLException}s.
     *
     * @param t The input argument
     * @return The computed result
     * @throws SQLException If an SQL-related error occurs
     */
    R applyThrows(T t) throws SQLException;

    /**
     * Applies this function while automatically wrapping checked
     * {@link SQLException}s into runtime exceptions.
     *
     * @param t The input argument
     * @return The computed result
     * @throws RuntimeException If an SQL exception occurs
     */
    @Override
    default R apply(T t) {
        try {
            return this.applyThrows(t);
        } catch (SQLException e) {
            throw new RuntimeException("There has been an sql exception!", e);
        }
    }
}
