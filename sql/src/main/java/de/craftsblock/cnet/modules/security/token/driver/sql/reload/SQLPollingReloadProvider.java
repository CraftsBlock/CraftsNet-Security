package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.CraftsNetSecuritySQLDriver;
import de.craftsblock.cnet.modules.security.token.driver.sql.SQLStoreDriver;
import de.craftsblock.craftsnet.logging.Logger;
import org.jetbrains.annotations.NotNull;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SQLPollingReloadProvider extends SQLReloadProvider implements Runnable {

    private static final String SQL_UPDATE_CHECK = """
            SELECT "global" AS `entity`, MAX(`created_at`) AS `last_action`
            FROM `cnet_security_entity_scopes`
            
            UNION ALL
            
            SELECT "tokens" AS `entity`, MAX(`updated_at`) AS `last_action`
            FROM `cnet_security_tokens`
            
            UNION ALL
            
            SELECT "token_groups" AS `entity`, MAX(`created_at`) AS `last_action`
            FROM `cnet_security_token_groups`
            
            UNION ALL
            
            SELECT "groups" AS `entity`, MAX(`created_at`) AS `last_action`
            FROM `cnet_security_groups`;""";

    private final Map<String, Timestamp> lastActions = new HashMap<>(4);
    private final ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
    private final CraftsNetSecuritySQLDriver craftsNetSecuritySQLDriver = CraftsNetSecuritySQLDriver.getInstance();

    public SQLPollingReloadProvider(@NotNull SQLStoreDriver driver) {
        this(driver, 5, 15, TimeUnit.SECONDS);
    }

    public SQLPollingReloadProvider(@NotNull SQLStoreDriver driver, long initialDelay, long delay, @NotNull TimeUnit unit) {
        super(driver);
        executor.scheduleWithFixedDelay(this, initialDelay, delay, unit);
    }

    @Override
    public synchronized void run() {
        this.query(this.preparedStatement(SQL_UPDATE_CHECK), resultSet -> {
            boolean reloadGroups = false;
            boolean reloadTokens = false;

            while (resultSet.next()) {
                final String entity = resultSet.getString("entity");
                final Timestamp lastAction = resultSet.getTimestamp("last_action");
                final Timestamp lastKnownAction = lastActions.get(entity);

                if (Objects.equals(lastAction, lastKnownAction)) {
                    continue;
                }

                if (lastAction == null) {
                    lastActions.remove(entity);
                } else {
                    lastActions.put(entity, lastAction);
                }

                switch (entity) {
                    case "global" -> {
                        reloadGroups = true;
                        reloadTokens = true;
                    }
                    case "groups" -> reloadGroups = true;
                    case "tokens", "token_groups" -> reloadTokens = true;
                }
            }

            Logger logger = CraftsNetSecuritySQLDriver.getInstance().getLogger();
            if (reloadGroups && reloadTokens) {
                logger.debug("Detected db change, reloading full driver.");
                getDriver().reload();
                return null;
            }

            if (reloadGroups) {
                logger.debug("Detected db group entity change, reloading group driver.");
                getDriver().getGroupStoreDriver().reload();
            }

            if (reloadTokens) {
                logger.debug("Detected db token entity change, reloading token driver.");
                getDriver().getTokenStoreDriver().reload();
            }

            return null;
        });
    }

    @Override
    public void close() {
        final Logger logger = craftsNetSecuritySQLDriver.getLogger();

        try {
            executor.shutdown();
            if (executor.awaitTermination(5, TimeUnit.SECONDS)) {
                return;
            }
        } catch (InterruptedException ignored) {
        }

        logger.error("Canceled and dropped " + executor.shutdownNow().size() + " tasks!");
    }

}
