package de.craftsblock.cnet.modules.security.token.driver.sql;

import java.sql.Connection;
import java.util.function.Supplier;

public sealed abstract class AbstractSQLStoreDriver extends SQLWorker
        permits SQLGroupStoreDriver, SQLScopeDriver, SQLTokenStoreDriver {

    public AbstractSQLStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

}
