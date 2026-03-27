package de.craftsblock.cnet.modules.security.token.setup;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.auth.AuthChain;
import de.craftsblock.cnet.modules.security.token.adapter.HttpTokenAuthAdapter;
import de.craftsblock.cnet.modules.security.token.adapter.HttpTokenAuthType;
import de.craftsblock.cnet.modules.security.token.adapter.WebSocketTokenAuthAdapter;
import de.craftsblock.cnet.modules.security.token.group.GroupRequirement;
import de.craftsblock.cnet.modules.security.token.group.GroupResolveMiddleware;
import de.craftsblock.cnet.modules.security.token.listener.WebSocketRevalidateCacheListener;
import de.craftsblock.cnet.modules.security.token.scope.ScopeRequirement;
import de.craftsblock.cnet.modules.security.token.scope.ScopeResolveMiddleware;
import de.craftsblock.craftscore.event.ListenerRegistry;
import de.craftsblock.craftsnet.addon.loaders.CraftsNetClassLoader;
import de.craftsblock.craftsnet.api.requirements.RequirementRegistry;
import org.jetbrains.annotations.NotNull;

import java.util.EnumMap;

public class TokenSystem {

    private static class Lock {
        private static final Lock SYNC_LOCK = new Lock();
    }

    private static final EnumMap<HttpTokenAuthType, String> httpTokenLocations = new EnumMap<>(HttpTokenAuthType.class);
    private static boolean setUp = false;

    private TokenSystem() {
    }

    public static String setHttpTokenLocation(HttpTokenAuthType type) {
        return setHttpTokenLocation(type, type.ensureDefaultLocation());
    }

    public static String setHttpTokenLocation(@NotNull HttpTokenAuthType type, @NotNull String location) {
        synchronized (Lock.SYNC_LOCK) {
            return httpTokenLocations.put(type, location);
        }
    }

    public static Builder builder() {
        ensureNotSetUp();
        if (CraftsNetClassLoader.retrieveCraftsNet() == null) {
            throw new IllegalStateException("Invocation outside craftsnet context prohibited!");
        }

        CraftsNetSecurity security = CraftsNetSecurity.getInstance();
        if (security == null) {
            throw new IllegalStateException("No instance of " + CraftsNetSecurity.class.getSimpleName() + "found!");
        }

        return new Builder(security);
    }

    public static boolean isSetUp() {
        return setUp;
    }

    private static void ensureNotSetUp() {
        if (!setUp) {
            return;
        }

        throw new IllegalStateException("Already set up!");
    }

    public static class Builder {

        private final CraftsNetSecurity craftsNetSecurity;

        private Builder(CraftsNetSecurity craftsNetSecurity) {
            this.craftsNetSecurity = craftsNetSecurity;
        }

        public Builder setHttpTokenLocation(HttpTokenAuthType type) {
            return this.setHttpTokenLocation(type, type.ensureDefaultLocation());
        }

        public Builder setHttpTokenLocation(@NotNull HttpTokenAuthType type, @NotNull String location) {
            synchronized (Lock.SYNC_LOCK) {
                httpTokenLocations.put(type, location);
            }
            return this;
        }

        public void build() {
            synchronized (Lock.SYNC_LOCK) {
                ensureNotSetUp();
                try {
                    ListenerRegistry listenerRegistry = craftsNetSecurity.getListenerRegistry();
                    listenerRegistry.register(new GroupResolveMiddleware());
                    listenerRegistry.register(new WebSocketRevalidateCacheListener());
                    listenerRegistry.register(new ScopeResolveMiddleware());
                    listenerRegistry.register(new WebSocketTokenAuthAdapter());

                    RequirementRegistry requirementRegistry = craftsNetSecurity.getRequirementRegistry();
                    requirementRegistry.register(new ScopeRequirement.Http());
                    requirementRegistry.register(new ScopeRequirement.WebSocket());
                    requirementRegistry.register(new GroupRequirement.Http());
                    requirementRegistry.register(new GroupRequirement.WebSocket());

                    AuthChain authChain = CraftsNetSecurity.getAuthChain();
                    authChain.append(new HttpTokenAuthAdapter(httpTokenLocations));
                    authChain.append(new WebSocketTokenAuthAdapter());
                } finally {
                    setUp = true;
                }
            }
        }

    }

}
