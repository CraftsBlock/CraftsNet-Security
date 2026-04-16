package de.craftsblock.cnet.modules.security.auth.autoregister;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.auth.adapter.AuthAdapter;
import de.craftsblock.craftsnet.addon.loaders.CraftsNetClassLoader;
import de.craftsblock.craftsnet.autoregister.AutoRegisterHandler;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegisterInfo;

public class AuthChainAutoRegisterHandler extends AutoRegisterHandler<AuthAdapter> {

    private final AuthChain authChain;

    /**
     *
     * Constructs an {@link AuthChainAutoRegisterHandler}.
     */
    public AuthChainAutoRegisterHandler() {
        super(CraftsNetClassLoader.retrieveCraftsNet());
        this.authChain = CraftsNetSecurity.getAuthChain();
    }

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
