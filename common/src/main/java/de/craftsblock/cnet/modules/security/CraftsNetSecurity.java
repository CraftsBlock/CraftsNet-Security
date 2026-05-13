package de.craftsblock.cnet.modules.security;

import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.auth.autoregister.AuthChainAutoRegisterHandler;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import de.craftsblock.craftsnet.autoregister.AutoRegisterRegistry;
import org.jetbrains.annotations.NotNull;

/**
 * Main addon entry point for the CraftsNet security module.
 * <p>
 * This addon provides the foundation for authentication chain support
 * within the CraftsNet framework. Authentication chains act as request
 * validation pipelines that must be passed successfully in order for
 * a request to be considered authenticated.
 * <p>
 * During the loading phase, the addon initializes the global
 * {@link AuthChain} instance and registers the
 * {@link AuthChainAutoRegisterHandler} for automatic authentication
 * chain registration support.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@Meta(name = "CraftsNetSecurity")
public final class CraftsNetSecurity extends Addon {

    /**
     * The current version of the security module.
     */
    public static final String VERSION = "1.0.0-pre3";

    private AuthChain authChain;

    /**
     * Initializes the security module and prepares all required
     * authentication components.
     * <p>
     * This includes creating the global {@link AuthChain} instance
     * and registering the {@link AuthChainAutoRegisterHandler}
     * within the {@link AutoRegisterRegistry}.
     */
    @Override
    public void onLoad() {
        super.onLoad();
        this.authChain = new AuthChain();

        AutoRegisterRegistry autoRegisterRegistry = this.getAutoRegisterRegistry();
        autoRegisterRegistry.register(new AuthChainAutoRegisterHandler());
    }

    /**
     * Called when the addon gets enabled.
     */
    @Override
    public void onEnable() {
        super.onEnable();
    }

    /**
     * Called when the addon gets disabled.
     */
    @Override
    public void onDisable() {
        super.onDisable();
    }

    /**
     * Retrieves the global authentication chain instance.
     *
     * @return The active {@link AuthChain} instance.
     */
    public static @NotNull AuthChain getAuthChain() {
        return getInstance().authChain;
    }

    /**
     * Retrieves the active addon instance.
     *
     * @return The singleton instance of {@link CraftsNetSecurity}.
     */
    public static CraftsNetSecurity getInstance() {
        return getAddon(CraftsNetSecurity.class);
    }

}
