package de.craftsblock.cnet.modules.security;

import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.token.TokenManager;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.group.GroupManager;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;

@Meta(name = "CNetSecurity")
public class CraftsNetSecurity extends Addon {

    public static final String VERSION = "1.0.0-pre1";

    private AuthChain authChain;

    private GroupManager groupManager;
    private TokenManager tokenManager;

    private StoreDriver storeDriver;

    public static void main(String[] args) throws IOException {
        CraftsNet.create(CraftsNetSecurity.class)
                .withArgs(args)
                .build();
    }

    @Override
    public void onLoad() {
        super.onLoad();
        this.authChain = new AuthChain();
        this.groupManager = new GroupManager();
        this.tokenManager = new TokenManager();
    }

    @Override
    public void onEnable() {
        super.onEnable();
    }

    @Override
    public void onDisable() {
        super.onDisable();
        this.storeDriver.close();
    }

    public static @NotNull AuthChain getAuthChain() {
        return getInstance().authChain;
    }

    public synchronized static void setGroupManager(@NotNull GroupManager groupManager) {
        getInstance().groupManager = groupManager;
    }

    public synchronized static @NotNull GroupManager getGroupManager() {
        return getInstance().groupManager;
    }

    public synchronized static void setTokenManager(@NotNull TokenManager tokenManager) {
        getInstance().tokenManager = tokenManager;
    }

    public synchronized static @NotNull TokenManager getTokenManager() {
        return getInstance().tokenManager;
    }

    public synchronized static void setStoreDriver(@NotNull StoreDriver storeDriver) {
        getInstance().storeDriver = storeDriver;
    }

    public synchronized static StoreDriver getStoreDriver() {
        return getInstance().storeDriver;
    }

    public static CraftsNetSecurity getInstance() {
        return getAddon(CraftsNetSecurity.class);
    }

}
