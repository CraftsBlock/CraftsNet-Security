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
                "ADD UNIQUE `unique_token_scope` (`token_id`, `scope_id`);"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_entity_scopes` " +
                "ADD UNIQUE `unique_group_scope` (`group_id`, `scope_id`);"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_token_groups` " +
                "ADD UNIQUE `unique_token_group` (`token_id`, `group_id`);"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_groups` " +
                "ADD UNIQUE `unique_group_name` (`name`, `id`);"));
        return true;
    }

    @Override
    public boolean downgrade() {
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_entity_scopes` " +
                "DROP UNIQUE `unique_token_scope`;"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_entity_scopes` " +
                "DROP UNIQUE `unique_group_scope`;"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_token_groups` " +
                "DROP UNIQUE `unique_token_group`;"));
        this.update(this.preparedStatement("ALTER TABLE `cnet_security_groups` " +
                "DROP UNIQUE `unique_group_name`;"));
        return true;
    }

}
