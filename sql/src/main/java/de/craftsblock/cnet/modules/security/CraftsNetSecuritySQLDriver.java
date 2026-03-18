package de.craftsblock.cnet.modules.security;

import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;

@Meta(name = "CraftsNetSecuritySQLDriver")
@Depends(CraftsNetSecurity.class)
public class CraftsNetSecuritySQLDriver extends Addon {

    public static CraftsNetSecuritySQLDriver getInstance() {
        return getAddon(CraftsNetSecuritySQLDriver.class);
    }

}
