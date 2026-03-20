package de.craftsblock.cnet.modules.security;

import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;

@Meta(name = "CraftsNetSecuritySQLDriver")
@Depends(CraftsNetSecurity.class)
public class CraftsNetSecuritySQLDriver extends Addon {

    public static final String VERSION = "1.0.0-pre1";

    public static void main(String[] args) throws IOException {
        CraftsNet.create(CraftsNetSecuritySQLDriver.class)
                .withArgs(args)
                .build();
    }

    public static CraftsNetSecuritySQLDriver getInstance() {
        return getAddon(CraftsNetSecuritySQLDriver.class);
    }

}
