package de.craftsblock.cnet.modules.security.token.driver.sql;

import java.sql.Connection;
import java.util.function.Supplier;

/**
 * Base implementation for all SQL-backed token store drivers.
 * <p>
 * This abstract class extends {@link SQLWorker} and acts as a shared
 * superclass for all SQL persistence implementations used by the
 * CraftsNet Security Token module.
 * <p>
 * It provides access to the common JDBC utility functionality implemented
 * by {@link SQLWorker} while restricting inheritance to known internal
 * driver implementations through the Java sealed class mechanism.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public sealed abstract class AbstractSQLStoreDriver extends SQLWorker
        permits SQLGroupStoreDriver, SQLScopeDriver, SQLTokenStoreDriver {

    /**
     * Creates a new SQL store driver using the given connection supplier.
     *
     * @param connectionSupplier Supplier providing JDBC connections
     */
    public AbstractSQLStoreDriver(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
    }

}
