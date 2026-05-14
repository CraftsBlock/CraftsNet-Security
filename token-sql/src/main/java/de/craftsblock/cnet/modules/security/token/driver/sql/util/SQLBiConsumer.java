package de.craftsblock.cnet.modules.security.token.driver.sql.util;

import java.sql.SQLException;
import java.util.function.BiConsumer;

/**
 * Functional SQL-aware extension of {@link BiConsumer}.
 * <p>
 * This interface allows lambda expressions and method references to throw
 * {@link SQLException}s while still remaining compatible with standard
 * {@link BiConsumer} usage. Checked SQL exceptions are automatically wrapped
 * into {@link RuntimeException}s by the default implementation.
 *
 * @param <T> The type of the first argument
 * @param <U> The type of the second argument
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@FunctionalInterface
public interface SQLBiConsumer<T, U> extends BiConsumer<T, U> {

    /**
     * Performs this operation and allows throwing {@link SQLException}s.
     *
     * @param t The first input argument
     * @param u The second input argument
     * @throws SQLException If an SQL-related error occurs
     */
    void acceptThrows(T t, U u) throws SQLException;

    /**
     * Performs this operation while automatically wrapping checked
     * {@link SQLException}s into runtime exceptions.
     *
     * @param t The first input argument
     * @param u The second input argument
     * @throws RuntimeException If an SQL exception occurs
     */
    @Override
    default void accept(T t, U u) {
        try {
            this.acceptThrows(t, u);
        } catch (SQLException e) {
            throw new RuntimeException("There has been an sql exception!", e);
        }
    }
}
