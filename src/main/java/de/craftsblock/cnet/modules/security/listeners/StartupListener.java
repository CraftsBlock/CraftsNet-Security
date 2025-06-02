package de.craftsblock.cnet.modules.security.listeners;

import de.craftsblock.cnet.modules.security.auth.token.TokenManager;
import de.craftsblock.cnet.modules.security.auth.token.driver.storage.FileTokenStorageDriver;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.events.addons.AllAddonsLoadedEvent;

/**
 * Initializes security related components after all addons have been loaded.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @since 1.0.0-SNAPSHOT
 */
@AutoRegister
public class StartupListener implements ListenerAdapter {

    /**
     * Handles the {@link AllAddonsLoadedEvent} to initialize the token storage driver if none is set.
     *
     * @param event The {@link AllAddonsLoadedEvent} triggered when all addons have been loaded.
     */
    @EventHandler
    public void handleAllAddonLoaded(AllAddonsLoadedEvent event) {
        if (TokenManager.getDriver() != null) return;
        TokenManager.setDriver(new FileTokenStorageDriver());
    }

}
