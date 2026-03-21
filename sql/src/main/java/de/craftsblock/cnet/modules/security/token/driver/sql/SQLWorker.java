package de.craftsblock.cnet.modules.security.token.driver.sql;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.sql.util.SQLFunction;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class SQLWorker {

    private final Supplier<Connection> connectionSupplier;

    public SQLWorker(Supplier<Connection> connectionSupplier) {
        this.connectionSupplier = connectionSupplier;
    }

    protected final void update(PreparedStatement statement) {
        ensureOpen();

        try (statement) {
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Could not perform update: " + e.getMessage(), e);
        }
    }

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

    protected final PreparedStatement preparedStatement(String sql, Object... values) {
        return this.preparedStatementList(sql, List.of(values));
    }

    protected final <T> PreparedStatement preparedStatementList(String sql, Collection<T> values) {
        ensureOpen();
        try {
            synchronized (connectionSupplier) {
                Connection connection = connectionSupplier.get();
                PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);

                AtomicInteger i = new AtomicInteger(0);
                for (T value : values) {
                    statement.setObject(i.incrementAndGet(), value);
                }

                return statement;
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not prepare statement: " + e.getMessage(), e);
        }
    }

    protected final <T> Collection<T> queryCollection(PreparedStatement statement, String column, Class<T> type) {
        return this.query(statement, result -> {
            Collection<T> values = new ArrayList<>();
            while (result.next()) {
                values.add(result.getObject(column, type));
            }

            return values;
        });
    }

    protected final boolean performScript(String name) {
        Logger logger = CraftsNetSecurity.getInstance().getLogger();

        try (InputStream file = getClass().getResourceAsStream(name)) {
            if (file == null) {
                logger.error("Could not find migration script: %s", name);
                return false;
            }

            synchronized (connectionSupplier) {
                Connection connection = connectionSupplier.get();
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
            }
        } catch (Exception e) {
            logger.error("Failed to upgrade: " + e.getMessage(), e);
            return false;
        }
    }

    public void ensureOpen() {
        try {
            synchronized (connectionSupplier) {
                Connection connection = connectionSupplier.get();
                if (connection.isClosed() || !connection.isValid(15)) {
                    throw new IllegalStateException("No operations allowed after underlying closure!");
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not check connection state: " + e.getMessage(), e);
        }
    }

    public Supplier<Connection> getConnectionSupplier() {
        return connectionSupplier;
    }

}
