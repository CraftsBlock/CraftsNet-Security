package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.token.adapter.HttpTokenAuthAdapter;
import de.craftsblock.cnet.modules.security.token.adapter.HttpTokenAuthType;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.group.GroupManager;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import org.jetbrains.annotations.NotNull;

import java.util.EnumMap;

@Meta(name = "CraftsNetSecurityToken")
@Depends(CraftsNetSecurity.class)
public class CraftsNetSecurityToken extends Addon {

    public static final String VERSION = CraftsNetSecurity.VERSION;
    private static final EnumMap<HttpTokenAuthType, String> HTTP_TOKEN_LOCATIONS = new EnumMap<>(HttpTokenAuthType.class);

    private GroupManager groupManager;
    private TokenManager tokenManager;

    private StoreDriver storeDriver;

    @Override
    public void onLoad() {
        super.onLoad();

        this.groupManager = new GroupManager();
        this.tokenManager = new TokenManager();

        AuthChain authChain = CraftsNetSecurity.getAuthChain();
        authChain.append(new HttpTokenAuthAdapter(HTTP_TOKEN_LOCATIONS));
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

    public static String setHttpTokenLocation(HttpTokenAuthType type) {
        return setHttpTokenLocation(type, type.ensureDefaultLocation());
    }

    public static String setHttpTokenLocation(@NotNull HttpTokenAuthType type, @NotNull String location) {
        synchronized (HTTP_TOKEN_LOCATIONS) {
            return HTTP_TOKEN_LOCATIONS.put(type, location);
        }
    }

    public static CraftsNetSecurityToken getInstance() {
        return getAddon(CraftsNetSecurityToken.class);
    }

}
