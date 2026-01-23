package de.craftsblock.cnet.modules.security.token.listener;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.file.FileTokenStoreDriver;
import de.craftsblock.craftscore.event.EventHandler;
import de.craftsblock.craftscore.event.EventPriority;
import de.craftsblock.craftscore.event.ListenerAdapter;
import de.craftsblock.craftsnet.events.addons.AllAddonsLoadedEvent;

import java.nio.file.Path;

public class TokenPostSetupListener implements ListenerAdapter {

    @EventHandler(priority = EventPriority.HIGHEST)
    public void handleAllAddonsLoaded(AllAddonsLoadedEvent event) {
        TokenStoreDriver currentDriver = CraftsNetSecurity.getTokenStoreDriver();
        if (currentDriver != null) {
            return;
        }

        Path dataPath = CraftsNetSecurity.getInstance().getDataPath();
        CraftsNetSecurity.setTokenStoreDriver(new FileTokenStoreDriver(dataPath.resolve("tokens.json")));
    }

}
