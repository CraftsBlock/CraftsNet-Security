package de.craftsblock.cnet.modules.security.token.driver.sql.schema;

import de.craftsblock.cnet.modules.security.token.driver.sql.SQLWorker;

public abstract class SQLSchemaUpgrade extends SQLWorker {

    private final SQLSchemaUpdater updater;
    private final String version;

    public SQLSchemaUpgrade(SQLSchemaUpdater updater, String version) {
        super(updater.getConnectionSupplier());
        this.updater = updater;
        this.version = version;
    }

    public abstract boolean upgrade();

    public abstract boolean downgrade();

    public SQLSchemaUpdater getUpdater() {
        return updater;
    }

    public String getVersion() {
        return version;
    }

}
