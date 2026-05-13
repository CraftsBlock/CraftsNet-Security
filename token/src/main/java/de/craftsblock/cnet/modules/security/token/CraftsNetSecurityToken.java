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
import org.intellij.lang.annotations.MagicConstant;
import org.jetbrains.annotations.NotNull;

import java.util.EnumMap;

@Meta(name = "CraftsNetSecurityToken")
@Depends(CraftsNetSecurity.class)
public class CraftsNetSecurityToken extends Addon {

    /**
     * Current version of the token security module.
     * <p>
     * This version is synchronized with the base security module.
     */
    public static final String VERSION = CraftsNetSecurity.VERSION;
    private static final EnumMap<HttpTokenAuthType, String> HTTP_TOKEN_LOCATIONS = new EnumMap<>(HttpTokenAuthType.class);

    private GroupManager groupManager;
    private TokenManager tokenManager;

    private StoreDriver storeDriver;

    /**
     * Initializes the token module and registers its authentication
     * adapter into the global authentication chain.
     * <p>
     * This includes initializing the {@link GroupManager},
     * {@link TokenManager}, and registering the
     * {@link HttpTokenAuthAdapter} for HTTP authentication.
     */
    @Override
    public void onLoad() {
        super.onLoad();

        this.groupManager = new GroupManager();
        this.tokenManager = new TokenManager();

        AuthChain authChain = CraftsNetSecurity.getAuthChain();
        authChain.append(new HttpTokenAuthAdapter(HTTP_TOKEN_LOCATIONS));
    }

    /**
     * Called when the addon is enabled.
     */
    @Override
    public void onEnable() {
        super.onEnable();
    }

    /**
     * Called when the addon is disabled.
     * <p>
     * Ensures that the configured {@link StoreDriver} is properly
     * closed and resources are released.
     */
    @Override
    public void onDisable() {
        super.onDisable();
        this.storeDriver.close();
    }

    /**
     * Sets the global group manager instance.
     *
     * @param groupManager The group manager to use.
     */
    public synchronized static void setGroupManager(@NotNull GroupManager groupManager) {
        getInstance().groupManager = groupManager;
    }

    /**
     * Retrieves the active group manager instance.
     *
     * @return The current {@link GroupManager}.
     */
    public synchronized static @NotNull GroupManager getGroupManager() {
        return getInstance().groupManager;
    }

    /**
     * Sets the global token manager instance.
     *
     * @param tokenManager The token manager to use.
     */
    public synchronized static void setTokenManager(@NotNull TokenManager tokenManager) {
        getInstance().tokenManager = tokenManager;
    }

    /**
     * Retrieves the active token manager instance.
     *
     * @return The current {@link TokenManager}.
     */
    public synchronized static @NotNull TokenManager getTokenManager() {
        return getInstance().tokenManager;
    }

    /**
     * Sets the persistent store driver used for token storage.
     *
     * @param storeDriver The store driver implementation.
     */
    public synchronized static void setStoreDriver(@NotNull StoreDriver storeDriver) {
        getInstance().storeDriver = storeDriver;
    }

    /**
     * Retrieves the active store driver instance.
     *
     * @return The configured {@link StoreDriver}, or {@code null} if not set.
     */
    public synchronized static StoreDriver getStoreDriver() {
        return getInstance().storeDriver;
    }

    /**
     * Registers a default HTTP token location based on the given type.
     * <p>
     * <strong>Important:</strong> Currently only {@link HttpTokenAuthType#HEADER} is accepted in this method.
     *
     * @param type The authentication type defining the token location.
     * @return The previously registered location, or {@code null} if none existed.
     */
    public static String setHttpTokenLocation(HttpTokenAuthType type) {
        return setHttpTokenLocation(type, type.ensureDefaultLocation());
    }

    /**
     * Registers a custom HTTP token location for the given type.
     *
     * @param type     The authentication type.
     * @param location The HTTP location where the token is expected.
     * @return The previously registered location, or {@code null} if none existed.
     */
    public static String setHttpTokenLocation(@NotNull HttpTokenAuthType type, @NotNull String location) {
        synchronized (HTTP_TOKEN_LOCATIONS) {
            return HTTP_TOKEN_LOCATIONS.put(type, location);
        }
    }

    /**
     * Retrieves the active addon instance.
     *
     * @return The singleton instance of {@link CraftsNetSecurityToken}.
     */
    public static CraftsNetSecurityToken getInstance() {
        return getAddon(CraftsNetSecurityToken.class);
    }

}
