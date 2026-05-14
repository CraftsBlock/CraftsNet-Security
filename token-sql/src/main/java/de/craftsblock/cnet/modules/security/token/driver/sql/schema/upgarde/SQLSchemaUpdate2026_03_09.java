package de.craftsblock.cnet.modules.security.token.driver.sql.schema.upgarde;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpdater;
import de.craftsblock.cnet.modules.security.token.driver.sql.schema.SQLSchemaUpgrade;

/**
 * Initial database schema installation for the token SQL driver.
 * <p>
 * This schema upgrade installs all required database tables, relations,
 * and triggers required for token, group, and scope persistence.
 * <p>
 * Additionally, validation triggers are created to enforce integrity
 * constraints on polymorphic scope assignments inside the
 * {@code cnet_security_entity_scopes} table.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class SQLSchemaUpdate2026_03_09 extends SQLSchemaUpgrade {

    /**
     * Creates the initial schema upgrade definition.
     *
     * @param updater The schema updater managing this upgrade
     */
    public SQLSchemaUpdate2026_03_09(SQLSchemaUpdater updater) {
        super(updater, "2026-03-09");
    }

    /**
     * Installs the initial database schema and creates validation triggers.
     *
     * @return {@code true} if the upgrade completed successfully,
     * otherwise {@code false}
     */
    @Override
    public boolean upgrade() {
        boolean success = performScript("/sql/schema/install.sql");
        success &= createTrigger("INSERT");
        success &= createTrigger("UPDATE");
        return success;
    }

    /**
     * Removes the installed database schema.
     *
     * @return {@code true} if the downgrade completed successfully,
     * otherwise {@code false}
     */
    @Override
    public boolean downgrade() {
        return performScript("/sql/schema/deinstall.sql");
    }

    /**
     * Creates a database trigger used to validate entity scope assignments.
     * <p>
     * The generated trigger ensures that exactly one relation target
     * is defined for each scope mapping entry. Either a token reference
     * or a group reference must be present, but never both.
     *
     * @param variation The SQL trigger variation, such as {@code INSERT}
     *                  or {@code UPDATE}
     * @return {@code true} if the trigger was created successfully,
     * otherwise {@code false}
     */
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
