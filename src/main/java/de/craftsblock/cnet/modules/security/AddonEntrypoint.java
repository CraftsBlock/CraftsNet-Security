package de.craftsblock.cnet.modules.security;

import de.craftsblock.cnet.modules.security.auth.AuthChainManager;
import de.craftsblock.cnet.modules.security.auth.chains.SimpleAuthChain;
import de.craftsblock.cnet.modules.security.auth.token.TokenManager;
import de.craftsblock.cnet.modules.security.ratelimit.RateLimitManager;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;

/**
 * The AccessControllerAddon class extends the base {@link Addon} class to provide specific functionality
 * for the access controller module.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.2
 * @since 1.0.0-SNAPSHOT
 */
@Meta(name = "CNetSecurity")
public class AddonEntrypoint extends Addon {

    /**
     * Called when the addon is loaded.
     */
    @Override
    public void onLoad() {
        // Set the instance
        CNetSecurity.register(this);
        CNetSecurity.register(this.logger());

        // Set environment variables
        CNetSecurity.register(new AuthChainManager());
        CNetSecurity.register(new TokenManager());
        CNetSecurity.register(new RateLimitManager());

        // Create a new default auth chain
        AuthChainManager chains = CNetSecurity.getAuthChainManager();
        if (chains != null) {
            SimpleAuthChain chain = new SimpleAuthChain();
            chains.add(chain);
            CNetSecurity.register(chain);
        }
    }

    /**
     * Called when the addon is disabled.
     */
    @Override
    public void onDisable() {
        CNetSecurity.getTokenManager().save();

        // Unset the instance
        CNetSecurity.unregister(this);
    }

}
