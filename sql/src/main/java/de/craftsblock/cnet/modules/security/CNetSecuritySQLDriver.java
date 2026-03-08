package de.craftsblock.cnet.modules.security;

import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;

@Meta(name = "CNetSecuritySQLDriver")
@Depends(CraftsNetSecurity.class)
public class CNetSecuritySQLDriver extends Addon {
}
