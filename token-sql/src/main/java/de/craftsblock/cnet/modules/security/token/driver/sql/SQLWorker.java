package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.sql.util.SQLBiConsumer;
import de.craftsblock.cnet.modules.security.token.driver.sql.util.SQLFunction;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * Base utility worker for executing SQL operations in a safe and convenience-oriented manner.
 * <p>
 * Implementations are expected to supply a valid {@link Connection} via the provided
 * {@link Supplier}. The worker itself does not manage connection pooling but only ensures
 * safe usage and lifecycle checks before executing operations.
 *
 * <p>
 * This class is primarily intended as an internal infrastructure component of the
 * CraftsNet Security Token SQL driver and should not be used directly outside of the
 * token persistence layer.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class SQLWorker implements AutoCloseable {

    private final @NotNull Supplier<@Nullable Connection> connectionSupplier;

    /**
     * Creates a new SQL worker using the given connection supplier.
     *
     * @param connectionSupplier Supplier providing JDBC connections for each operation
     */
    public SQLWorker(@NotNull Supplier<@Nullable Connection> connectionSupplier) {
        this.connectionSupplier = connectionSupplier;
    }

    /**
     * Executes an SQL update statement (INSERT, UPDATE, DELETE).
     * <p>
     * The statement is automatically closed after execution. Any SQL errors
     * are wrapped into a {@link RuntimeException}.
     *
     * @param statement The prepared statement to execute
     * @throws IllegalStateException if the underlying connection is closed
     */
    protected final void update(PreparedStatement statement) {
        ensureOpen();

        try (statement) {
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Could not perform update: " + e.getMessage(), e);
        }
    }

    /**
     * Executes a batch update for a collection of values.
     * <p>
     * Each value is bound using the provided {@link SQLBiConsumer} before being added
     * to the batch. The batch is executed in chunks to improve performance on large datasets.
     *
     * @param statement     The prepared statement used for batching
     * @param values        Collection of values to process
     * @param valueConsumer Consumer responsible for binding each value to the statement
     * @param <T>           Type of batched values
     * @throws IllegalStateException if the underlying connection is closed
     */
    protected final <T> void updateBatch(@NotNull PreparedStatement statement,
                                         @NotNull Collection<T> values,
                                         @NotNull SQLBiConsumer<PreparedStatement, T> valueConsumer) {
        ensureOpen();

        try (statement) {
            int batchSize = 500;
            int count = 0;

            for (T value : values) {
                valueConsumer.acceptThrows(statement, value);
                statement.addBatch();

                if (++count % batchSize == 0) {
                    statement.executeBatch();
                }
            }

            statement.executeBatch();
        } catch (SQLException e) {
            throw new RuntimeException("Could not perform batch: " + e.getMessage(), e);
        }
    }

    /**
     * Executes a query and maps the {@link ResultSet} to a custom return type.
     *
     * @param statement          The prepared statement to execute
     * @param resultSetRFunction Function used to transform the result set
     * @param <R>                Return type of the query
     * @return The mapped result
     * @throws IllegalStateException if the underlying connection is closed
     */
    protected final <R> R query(PreparedStatement statement, SQLFunction<ResultSet, R> resultSetRFunction) {
        ensureOpen();
        try (statement) {
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSetRFunction.applyThrows(resultSet);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not perform query: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a prepared statement with the given SQL and positional parameters.
     *
     * @param sql    SQL query string
     * @param values Parameters to bind to the statement
     * @return A prepared JDBC statement
     * @throws IllegalStateException if the underlying connection is closed
     */
    protected final PreparedStatement preparedStatement(String sql, Object... values) {
        return this.preparedStatementList(sql, List.of(values));
    }

    /**
     * Creates a prepared statement and binds a collection of parameters.
     *
     * @param sql    SQL query string
     * @param values Collection of values to bind
     * @param <T>    Type of parameters
     * @return A prepared JDBC statement
     */
    protected final <T> PreparedStatement preparedStatementList(String sql, Collection<T> values) {
        ensureOpen();
        try {
            Connection connection = getConnection();
            PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);

            AtomicInteger i = new AtomicInteger(0);
            for (T value : values) {
                statement.setObject(i.incrementAndGet(), value);
            }

            return statement;
        } catch (SQLException e) {
            throw new RuntimeException("Could not prepare statement: " + e.getMessage(), e);
        }
    }

    /**
     * Executes a query and collects a single column into a typed collection.
     *
     * @param statement SQL statement to execute
     * @param column    Column name to extract
     * @param type      Expected Java type of the column
     * @param <T>       Type of returned elements
     * @return Collection of mapped column values
     */
    protected final <T> Collection<T> queryCollection(PreparedStatement statement, String column, Class<T> type) {
        return this.query(statement, result -> {
            Collection<T> values = new ArrayList<>();
            while (result.next()) {
                values.add(result.getObject(column, type));
            }

            return values;
        });
    }

    /**
     * Executes a SQL migration script from the classpath.
     * <p>
     * The script is read line-by-line, comments and empty lines are ignored,
     * and statements are executed sequentially. The operation runs inside a
     * transaction and is committed upon success.
     *
     * @param name Resource path of the SQL script
     * @return {@code true} if execution succeeded, otherwise {@code false}
     */
    protected final boolean performScript(String name) {
        ensureOpen();
        Logger logger = CraftsNetSecurity.getInstance().getLogger();

        try (InputStream file = getClass().getResourceAsStream(name)) {
            if (file == null) {
                logger.error("Could not find migration script: %s", name);
                return false;
            }

            Connection connection = getConnection();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(file));
                 Statement statement = connection.createStatement()) {

                connection.setAutoCommit(false);

                StringBuilder currentStatement = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    line = line.trim();

                    if (line.isEmpty() || line.startsWith("--")) {
                        continue;
                    }

                    currentStatement.append(line).append(" ");

                    if (!line.endsWith(";")) {
                        continue;
                    }

                    String sql = currentStatement.toString();
                    sql = sql.substring(0, sql.lastIndexOf(";")).trim();

                    if (!sql.isEmpty()) {
                        statement.execute(sql);
                    }

                    currentStatement.setLength(0);
                }

                connection.commit();
                return true;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (Exception e) {
            logger.error("Failed to upgrade: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Closes the underlying JDBC connection if it is still open.
     * <p>
     * After closure, no further SQL operations should be executed.
     */
    @Override
    public void close() {
        try {
            Connection connection = getConnection();
            if (connection == null || connection.isClosed()) {
                return;
            }

            connection.close();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to close sql connection!", e);
        }
    }

    /**
     * Ensures that the underlying connection is still valid and open.
     *
     * @throws IllegalStateException if the connection is closed or unavailable
     */
    public void ensureOpen() {
        try {
            Connection connection = getConnection();
            if (connection == null || connection.isClosed()) {
                throw new IllegalStateException("No operations allowed after underlying closure!");
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not check connection state: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the connection supplier used by this worker.
     *
     * @return supplier providing JDBC connections
     */
    public Supplier<Connection> getConnectionSupplier() {
        return connectionSupplier;
    }

    /**
     * Obtains a JDBC connection from the configured supplier.
     *
     * @return active or newly created connection
     */
    public Connection getConnection() {
        return connectionSupplier.get();
    }

}
