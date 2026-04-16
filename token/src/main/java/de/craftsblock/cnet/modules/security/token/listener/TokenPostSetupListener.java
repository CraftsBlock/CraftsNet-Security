package de.craftsblock.cnet.modules.security.token.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.CraftsNetSecurityToken;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.file.FileStoreDriver;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftsnet.addon.meta.Startup;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.addons.AllAddonsLoadedEvent;
import org.jetbrains.annotations.ApiStatus;

import java.nio.file.Path;

@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class TokenPostSetupListener implements ListenerAdapter {

    @EventHandler(priority = EventPriority.HIGHEST)
    public void registerFallbackDriver(AllAddonsLoadedEvent event) {
        StoreDriver currentDriver = StoreDriver.getInstance();
        if (currentDriver != null) {
            return;
        }

        Path dataPath = CraftsNetSecurity.getInstance().getDataPath();
        FileStoreDriver driver = FileStoreDriver.create(
                dataPath.resolve("groups.json"),
                dataPath.resolve("tokens.json")
        );

        CraftsNetSecurityToken.setStoreDriver(driver);
    }

}
