package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;

@Meta(name = "CraftsNetSecurityTokenSQLDriver")
@Depends(CraftsNetSecurity.class)
@Depends(CraftsNetSecurityToken.class)
public final class CraftsNetSecurityTokenSQLDriver extends Addon {

    public static final String VERSION = CraftsNetSecurity.VERSION;

    @Override
    public void onDisable() {
        super.onDisable();
    }

    public static CraftsNetSecurityTokenSQLDriver getInstance() {
        return getAddon(CraftsNetSecurityTokenSQLDriver.class);
    }

}
