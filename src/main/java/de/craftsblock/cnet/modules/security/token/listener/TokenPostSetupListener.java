package de.craftsblock.cnet.modules.security.token.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.Driver;
import de.craftsblock.cnet.modules.security.token.driver.file.FileGroupStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.file.FileTokenStoreDriver;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.addons.AllAddonsLoadedEvent;

import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

@AutoRegister(startup = Startup.LOAD)
public class TokenPostSetupListener implements ListenerAdapter {

    @EventHandler(priority = EventPriority.HIGHEST)
    public void registerFallbackDriver(AllAddonsLoadedEvent event) {
        registerFallbackDriver(
                CraftsNetSecurity::getTokenStoreDriver,
                CraftsNetSecurity::setTokenStoreDriver,
                FileTokenStoreDriver::new,
                "tokens.json"
        );
        registerFallbackDriver(
                CraftsNetSecurity::getGroupStoreDriver,
                CraftsNetSecurity::setGroupStoreDriver,
                FileGroupStoreDriver::new,
                "groups.json"
        );
    }

    private <D extends Driver> void registerFallbackDriver(Supplier<D> current, Consumer<D> setter,
                                                           Function<Path, D> initiator, String file) {
        D currentDriver = current.get();
        if (currentDriver != null) {
            return;
        }

        Path dataPath = CraftsNetSecurity.getInstance().getDataPath();
        setter.accept(initiator.apply(dataPath.resolve(file)));
    }

}
