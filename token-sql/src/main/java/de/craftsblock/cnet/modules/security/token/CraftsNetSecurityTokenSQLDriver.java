package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;

/**
 * Addon entry point for the SQL-based implementation of the CraftsNet Security Token system.
 * <p>
 * This addon provides a persistence layer that replaces or extends the default token storage
 * mechanism with a SQL-backed {@link de.craftsblock.cnet.modules.security.token.driver.StoreDriver}
 * implementation. It is automatically loaded by the CraftsNet addon system and requires both
 * the core security module and the base token module to function correctly.
 * <p>
 * This class itself does not contain business logic but serves as a bootstrap and dependency
 * marker for the SQL driver integration.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see CraftsNetSecurity
 * @see CraftsNetSecurityToken
 * @since 1.0.0
 */
@Meta(name = "CraftsNetSecurityTokenSQLDriver")
@Depends(CraftsNetSecurity.class)
@Depends(CraftsNetSecurityToken.class)
public final class CraftsNetSecurityTokenSQLDriver extends Addon {

    /**
     * Version of this addon, aligned with the main CraftsNet Security version.
     */
    public static final String VERSION = CraftsNetSecurity.VERSION;

    /**
     * Called when the addon is being disabled by the CraftsNet addon lifecycle.
     * <p>
     * This implementation currently delegates to the superclass without additional logic,
     * but is kept for future cleanup or resource handling requirements.
     */
    @Override
    public void onDisable() {
        super.onDisable();
    }

    /**
     * Returns the singleton instance of this addon.
     *
     * @return the active {@link CraftsNetSecurityTokenSQLDriver} instance
     */
    public static CraftsNetSecurityTokenSQLDriver getInstance() {
        return getAddon(CraftsNetSecurityTokenSQLDriver.class);
    }

}
