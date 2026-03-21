package de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgardes;

import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpgrade;

public class SQLSchemaUpdate2026_03_21 extends SQLSchemaUpgrade {

    public SQLSchemaUpdate2026_03_21(SQLSchemaUpdater updater) {
        super(updater, "2026-03-21");
    }

    @Override
    public boolean upgrade() {
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_entity_scopes` " +
                "ADD INDEX `idx_token_scope` (`token_id`, `scope_id`);"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_token_groups` " +
                "ADD INDEX `idx_token_group` (`token_id`, `group_id`);"));
        return true;
    }

    @Override
    public boolean downgrade() {
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_entity_scopes` " +
                "DROP INDEX `idx_token_scope`;"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_token_groups` " +
                "DROP INDEX `idx_token_group`;"));
        return true;
    }

}
