package de.craftsblock.cnet.modules.security;

import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.auth.autoregister.AuthChainAutoRegisterHandler;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import de.craftsblock.craftsnet.autoregister.AutoRegisterRegistry;
import org.jetbrains.annotations.NotNull;

@Meta(name = "CraftsNetSecurity")
public final class CraftsNetSecurity extends Addon {

    public static final String VERSION = "1.0.0-pre1";

    private AuthChain authChain;

    @Override
    public void onLoad() {
        super.onLoad();
        this.authChain = new AuthChain();

        AutoRegisterRegistry autoRegisterRegistry = this.getAutoRegisterRegistry();
        autoRegisterRegistry.register(new AuthChainAutoRegisterHandler());
    }

    @Override
    public void onEnable() {
        super.onEnable();
    }

    @Override
    public void onDisable() {
        super.onDisable();
    }

    public static @NotNull AuthChain getAuthChain() {
        return getInstance().authChain;
    }

    public static CraftsNetSecurity getInstance() {
        return getAddon(CraftsNetSecurity.class);
    }

}
