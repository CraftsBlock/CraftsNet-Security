package de.craftsblock.cnet.modules.security.token.driver.sql;

import java.sql.Connection;
import java.util.function.Supplier;

public sealed abstract class AbstractSQLStoreDriver extends SQLWorker implements AutoCloseable
        permits SQLGroupStoreDriver, SQLScopeDriver, SQLTokenStoreDriver {

    private boolean closed = false;

    public AbstractSQLStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

    public final void ensureOpen() {
        super.ensureOpen();
        if (closed) {
            throw new IllegalStateException("No operations allowed after closure!");
        }
    }

    @Override
    public final void close() {
        ensureOpen();
        try {

        } finally {
            this.closed = true;
        }
    }

    public final boolean isClosed() {
        return closed;
    }

}
