package de.craftsblock.cnet.modules.security;

import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import de.craftsblock.craftsnet.builder.ActivateType;

import java.io.IOException;

@Meta(name = "CNetSecurity")
public class CraftsNetSecurity extends Addon {

    private AuthChain authChain;

    public static void main(String[] args) throws IOException {
        CraftsNet.create(CraftsNetSecurity.class)
                .withWebServer(ActivateType.ENABLED)
                .withWebSocketServer(ActivateType.ENABLED)
                .withFileLogger(ActivateType.DISABLED)
                .withDebug(true)
                .build();
    }

    @Override
    public void onLoad() {
        this.authChain = new AuthChain();
    }

    @Override
    public void onEnable() {
        super.onEnable();
    }

    @Override
    public void onDisable() {
        super.onDisable();
    }

    public static AuthChain getAuthChain() {
        return getInstance().authChain;
    }

    public static CraftsNetSecurity getInstance() {
        return getAddon(CraftsNetSecurity.class);
    }

}
