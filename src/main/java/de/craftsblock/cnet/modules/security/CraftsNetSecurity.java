package de.craftsblock.cnet.modules.security;

import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.token.TokenManager;
import de.craftsblock.cnet.modules.security.token.driver.GroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.group.GroupManager;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import de.craftsblock.craftsnet.builder.ActivateType;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;

@Meta(name = "CNetSecurity")
public class CraftsNetSecurity extends Addon {

    private AuthChain authChain;

    private GroupManager groupManager;
    private TokenManager tokenManager;

    private GroupStoreDriver groupStoreDriver;
    private TokenStoreDriver tokenStoreDriver;

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
        this.tokenStoreDriver.close();
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

    public synchronized static void setGroupStoreDriver(@NotNull GroupStoreDriver groupStoreDriver) {
        getInstance().groupStoreDriver = groupStoreDriver;
    }

    public synchronized static GroupStoreDriver getGroupStoreDriver() {
        return getInstance().groupStoreDriver;
    }

    public synchronized static void setTokenStoreDriver(@NotNull TokenStoreDriver tokenStoreDriver) {
        getInstance().tokenStoreDriver = tokenStoreDriver;
    }

    public synchronized static TokenStoreDriver getTokenStoreDriver() {
        return getInstance().tokenStoreDriver;
    }

    public static CraftsNetSecurity getInstance() {
        return getAddon(CraftsNetSecurity.class);
    }

}
