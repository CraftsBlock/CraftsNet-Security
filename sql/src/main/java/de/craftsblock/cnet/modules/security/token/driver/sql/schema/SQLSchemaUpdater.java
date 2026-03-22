package de.craftsblock.cnet.modules.security.token.driver.sql.schema;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.sql.SQLWorker;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgardes.SQLSchemaUpdate2026_03_09;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgardes.SQLSchemaUpdate2026_03_21;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.Contract;

import java.sql.Connection;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

public class SQLSchemaUpdater extends SQLWorker {

    public final LinkedList<SQLSchemaUpgrade> versions;

    public SQLSchemaUpdater(Supplier<Connection> connectionSupplier) {
        super(connectionSupplier);
        this.versions = new LinkedList<>(List.of(
                new SQLSchemaUpdate2026_03_09(this),
                new SQLSchemaUpdate2026_03_21(this)
        ));
    }

    public boolean needsUpgrade() {
        if (!isSchemaInstalled()) {
            return true;
        }

        String version = getCurrentInstalledVersion();
        return !versions.getLast().getVersion().equalsIgnoreCase(version);
    }

    public void performUpgrade() {
        Logger logger = CraftsNetSecurity.getInstance().getLogger();
        int offset;

        if (isSchemaInstalled()) {
            String currentInstalledVersion = getCurrentInstalledVersion();
            SQLSchemaUpgrade currentInstalled = getUpgrade(currentInstalledVersion);

            if (currentInstalled == null) {
                logger.error("Provided db schema is newer than any available schema updates.");
                logger.error("Are you operating two different versions of craftsnet security?");
                logger.error("Resuming with newer db schema %s, this may cause exceptions!",
                        currentInstalledVersion);
                logger.error("Consider updating to a newer version of craftsnet security!");
                return;
            }

            offset = versions.indexOf(currentInstalled);
        } else {
            offset = -1;
        }

        for (int i = offset + 1; i < versions.size(); i++) {
            SQLSchemaUpgrade update = versions.get(i);
            String version = update.getVersion();

            long start = System.currentTimeMillis();
            boolean success = update.upgrade();
            long executionTime = System.currentTimeMillis() - start;

            this.update(this.preparedStatement("""
                    INSERT INTO `cnet_security_schema_history`
                        (`version`, `execution_time`, `success`)
                    VALUES (?, ?, ?)
                    """, version, executionTime, success));

            if (!success) {
                throw new IllegalStateException("Failed to update db schema to " + version);
            } else {
                logger.debug("Installed db schema version %s after %sms",
                        version, executionTime);
            }
        }
    }

    @Contract("null -> null")
    public SQLSchemaUpgrade getUpgrade(String version) {
        if (version == null) {
            return null;
        }

        return versions.stream()
                .filter(upgrade -> upgrade.getVersion().equalsIgnoreCase(version))
                .findFirst()
                .orElse(null);
    }

    public boolean isSchemaInstalled() {
        return this.query(this.preparedStatement("""
                SELECT COUNT(*)
                FROM `information_schema`.`tables`
                WHERE `table_schema` = DATABASE()
                  AND `table_name` = 'cnet_security_schema_history';
                """), result -> result.next() && result.getInt(1) == 1);
    }

    public String getCurrentInstalledVersion() {
        return this.query(this.preparedStatement("""
                SELECT `version`
                FROM `cnet_security_schema_history`
                WHERE `success` = true
                ORDER BY `installed_on`, `id` DESC LIMIT 1;
                """), result -> result.next() ? result.getString("version") : null);
    }

}
