package de.craftsblock.cnet.modules.security.token.driver.sql.reload;

import de.craftsblock.cnet.modules.security.token.CraftsNetSecurityTokenSQLDriver;
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

/**
 * Polling-based SQL reload provider implementation.
 * <p>
 * This provider periodically checks database entities for changes by
 * comparing modification timestamps against previously known values.
 * Whenever changes are detected, the corresponding cache or driver
 * components are reloaded automatically.
 * <p>
 * The polling process is executed asynchronously using a scheduled
 * executor service.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
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
    private final CraftsNetSecurityTokenSQLDriver craftsNetSecurityTokenSQLDriver = CraftsNetSecurityTokenSQLDriver.getInstance();

    /**
     * Creates a new polling reload provider using default timing values.
     * <p>
     * Polling starts after an initial delay of 5 seconds and repeats
     * every 15 seconds.
     *
     * @param driver The SQL store driver associated with this provider
     */
    public SQLPollingReloadProvider(@NotNull SQLStoreDriver driver) {
        this(driver, 5, 15, TimeUnit.SECONDS);
    }

    /**
     * Creates a new polling reload provider.
     *
     * @param driver       The SQL store driver associated with this provider
     * @param initialDelay The initial delay before polling starts
     * @param delay        The delay between polling executions
     * @param unit         The time unit used for delay values
     */
    public SQLPollingReloadProvider(@NotNull SQLStoreDriver driver, long initialDelay, long delay, @NotNull TimeUnit unit) {
        super(driver);
        executor.scheduleWithFixedDelay(this, initialDelay, delay, unit);
    }

    /**
     * Performs a single polling cycle.
     * <p>
     * The provider checks for changed timestamps and reloads the affected
     * store drivers if modifications are detected.
     */
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

            Logger logger = CraftsNetSecurityTokenSQLDriver.getInstance().getLogger();
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

    /**
     * Stops the polling executor and waits for pending tasks to complete.
     * <p>
     * If shutdown does not complete within the timeout window, all
     * remaining tasks are canceled immediately.
     */
    @Override
    public void close() {
        final Logger logger = craftsNetSecurityTokenSQLDriver.getLogger();

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
