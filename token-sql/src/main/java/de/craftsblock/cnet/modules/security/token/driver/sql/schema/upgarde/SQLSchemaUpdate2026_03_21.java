package de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgarde;

import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpgrade;

/**
 * Schema upgrade introducing unique constraints for security relations.
 * <p>
 * This migration improves database consistency by preventing duplicate
 * scope and group mappings across tokens and groups.
 * <p>
 * Unique constraints are added to ensure that identical relations cannot
 * be inserted multiple times into relation tables.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class SQLSchemaUpdate2026_03_21 extends SQLSchemaUpgrade {

    /**
     * Creates the schema upgrade definition.
     *
     * @param updater The schema updater managing this upgrade
     */
    public SQLSchemaUpdate2026_03_21(SQLSchemaUpdater updater) {
        super(updater, "2026-03-21");
    }

    /**
     * Applies unique constraints to token, group, and scope relation tables.
     *
     * @return {@code true} always after successful execution
     */
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

    /**
     * Removes all unique constraints introduced by this migration.
     *
     * @return {@code true} always after successful execution
     */
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