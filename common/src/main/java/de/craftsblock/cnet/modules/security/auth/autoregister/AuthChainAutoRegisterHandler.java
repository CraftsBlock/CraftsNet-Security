package de.craftsblock.cnet.modules.security.auth.autoregister;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.auth.adapter.AuthAdapter;
import de.craftsblock.craftsnet.addon.loaders.CraftsNetClassLoader;
import de.craftsblock.craftsnet.autoregister.AutoRegisterHandler;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegisterInfo;

/**
 * Automatic registration handler responsible for registering
 * {@link AuthAdapter} implementations into the global
 * {@link AuthChain}.
 * <p>
 * This handler integrates with the CraftsNet auto registration
 * system and automatically appends discovered authentication
 * adapters to the authentication chain during the addon loading
 * process.
 * <p>
 * HTTP and websocket adapters are handled independently and
 * are only registered if they are not already present within
 * the corresponding adapter queue.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @see AuthChain
 * @see AuthAdapter
 * @since 1.0.0
 */
public class AuthChainAutoRegisterHandler extends AutoRegisterHandler<AuthAdapter> {

    private final AuthChain authChain;

    /**
     * Creates a new {@link AuthChainAutoRegisterHandler}.
     * <p>
     * The handler automatically retrieves the global
     * {@link AuthChain} instance from the active
     * {@link CraftsNetSecurity} addon.
     */
    public AuthChainAutoRegisterHandler() {
        super(CraftsNetClassLoader.retrieveCraftsNet());
        this.authChain = CraftsNetSecurity.getAuthChain();
    }

    /**
     * Handles the automatic registration of the given
     * {@link AuthAdapter}.
     * <p>
     * Depending on the implemented adapter interfaces,
     * the adapter is registered for HTTP authentication,
     * websocket authentication, or both.
     *
     * @param authAdapter The authentication adapter to register.
     * @param info        The auto registration metadata.
     * @param args        Additional registration arguments.
     * @return {@code true} if at least one adapter registration
     * was performed, otherwise {@code false}.
     */
    @Override
    protected boolean handle(AuthAdapter authAdapter, AutoRegisterInfo info, Object... args) {
        boolean success = false;

        if (authAdapter instanceof AuthAdapter.Http http
                && !authChain.isHttpAdapterRegistered(http)) {
            authChain.append(http);
            success = true;
        }

        if (authAdapter instanceof AuthAdapter.WebSocket webSocket
                && !authChain.isWebSocketAdapterRegistered(webSocket)) {
            authChain.append(webSocket);
            success = true;
        }

        return success;
    }

}
