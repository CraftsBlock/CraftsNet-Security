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

/**
 * Post-initialization listener responsible for ensuring that a valid
 * {@link StoreDriver} is available after all addons have been loaded.
 * <p>
 * If no external or preconfigured store driver has been registered by
 * other modules, this listener installs a default file-based implementation
 * using JSON storage files for groups and tokens.
 * <p>
 * This guarantees that the token system remains operational even without
 * a custom persistence backend.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @since 1.0.0
 */
@ApiStatus.Internal
@AutoRegister(startup = Startup.LOAD)
public class TokenPostSetupListener implements ListenerAdapter {

    /**
     * Registers a fallback file-based {@link StoreDriver} if none has been
     * configured by other addons.
     *
     * @param event event triggered once all addons have been fully loaded
     */
    @EventHandler(priority = EventPriority.LOW)
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
