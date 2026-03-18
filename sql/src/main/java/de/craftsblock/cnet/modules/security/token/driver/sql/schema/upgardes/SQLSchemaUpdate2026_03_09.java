package de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgardes;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpgrade;

public class SQLSchemaUpdate2026_03_09 extends SQLSchemaUpgrade {

    public SQLSchemaUpdate2026_03_09(SQLSchemaUpdater updater) {
        super(updater, "2026-03-09");
    }

    @Override
    public boolean upgrade() {
        boolean success = performScript("/sql/schema/install.sql");
        success &= createTrigger("INSERT");
        success &= createTrigger("UPDATE");
        return success;
    }

    @Override
    public boolean downgrade() {
        return performScript("/sql/schema/deinstall.sql");
    }

    private boolean createTrigger(String variation) {
        try {
            this.update(this.preparedStatement("""
                    CREATE TRIGGER IF NOT EXISTS `enforce_foreign_keys_on_%s`
                        BEFORE %s
                        ON `cnet_security_entity_scopes`
                        FOR EACH ROW
                    BEGIN
                        IF NEW.token_id IS NULL AND NEW.group_id IS NULL THEN
                            SIGNAL SQLSTATE '45000'
                            SET MESSAGE_TEXT = 'Either token_id or group_id must be provided.';
                        END IF;
                    
                        IF NEW.token_id IS NOT NULL AND NEW.group_id IS NOT NULL THEN
                            SIGNAL SQLSTATE '45000'
                            SET MESSAGE_TEXT = 'Only one of token_id or group_id can be provided, not both.';
                        END IF;
                    END
                    """.formatted(variation.toLowerCase(), variation.toUpperCase())));
            return true;
        } catch (Throwable t) {
            CraftsNetSecurity.getInstance().getLogger().error(
                    "Failed to create trigger in variation %s: %s",
                    t, variation, t.getMessage()
            );
            return false;
        }
    }

}
