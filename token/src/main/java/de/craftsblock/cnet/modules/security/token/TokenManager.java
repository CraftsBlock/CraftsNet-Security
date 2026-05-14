package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.event.TokenCreateEvent;
import de.craftsblock.cnet.modules.security.token.event.cache.RevalidateTokenCacheEvent;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.cnet.modules.security.token.util.CreatedToken;
import de.craftsblock.cnet.modules.security.token.util.TokenParts;
import de.craftsblock.cnet.modules.security.token.util.TokenUtil;
import de.craftsblock.craftscore.cache.LruCache;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Central manager responsible for creating, validating, caching,
 * and persisting security tokens.
 * <p>
 * This class acts as the main entry point for all token-related
 * operations within the CraftsNet security token module. It handles
 * token lifecycle management, including generation, validation,
 * persistence through a {@link StoreDriver}, and in-memory caching
 * using an LRU cache.
 * <p>
 * Additionally, this manager dispatches lifecycle events such as
 * {@link TokenCreateEvent} and cache revalidation events to the
 * global listener system.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see Token
 * @since 1.0.0
 */
public class TokenManager {

    private final LruCache<Long, Token> tokenCache;

    /**
     * Creates a token manager with a default cache size.
     */
    public TokenManager() {
        this(25);
    }

    /**
     * Creates a token manager with a custom LRU cache size.
     *
     * @param cacheSize The maximum number of cached tokens.
     */
    public TokenManager(int cacheSize) {
        this.tokenCache = new LruCache<>(cacheSize);
    }

    /**
     * Persists the given token using the configured store driver
     * and stores it in the local cache.
     *
     * @param token The token to persist.
     */
    public synchronized void persist(Token token) {
        StoreDriver.getInstance().saveToken(token);
        tokenCache.put(token.id(), token);
    }

    /**
     * Deletes the given token from persistent storage and cache.
     *
     * @param token The token to delete.
     */
    public synchronized void delete(Token token) {
        this.delete(token.id());
    }

    /**
     * Deletes a token by its identifier from persistent storage
     * and removes it from the cache.
     *
     * @param id The token identifier.
     */
    public synchronized void delete(long id) {
        StoreDriver.getInstance().deleteToken(id);
        removeCache(id);
    }

    /**
     * Retrieves a token by its identifier.
     * <p>
     * This method first checks the local cache before querying
     * the persistent store driver.
     *
     * @param id The token identifier.
     * @return The resolved token, or {@code null} if not found.
     */
    public synchronized Token get(long id) {
        if (tokenCache.containsKey(id)) {
            return tokenCache.get(id);
        }

        TokenStoreDriver driver = StoreDriver.getInstance();
        if (!driver.existsToken(id)) {
            return null;
        }

        Token token = driver.loadToken(id);
        tokenCache.put(token.id(), token);
        return token;
    }

    /**
     * Validates a raw token string and resolves the corresponding
     * {@link Token} if valid.
     * <p>
     * The token is split into its internal parts and validated
     * against the stored hash. The secret is securely erased after use.
     *
     * @param token The raw token string.
     * @return The resolved token if valid, otherwise {@code null}.
     */
    public synchronized Token getValidated(String token) {
        TokenParts parts = TokenUtil.splitToTokenParts(token);
        if (parts == null) {
            return null;
        }

        try {
            Token realToken = get(parts.id());
            if (realToken == null || !realToken.validate(parts.secret())) {
                return null;
            }

            return realToken;
        } finally {
            PassphraseUtils.erase(parts.secret());
        }
    }

    /**
     * Creates and persists a new token with the given scopes.
     *
     * @param scopes The scopes assigned to the token.
     * @return The created and persisted token.
     */
    public synchronized CreatedToken createPersisted(String... scopes) {
        return this.createPersisted(List.of(scopes), Collections.emptyList());
    }

    /**
     * Creates and persists a new token with scopes and groups.
     *
     * @param scopes The scopes assigned to the token.
     * @param groups The groups assigned to the token.
     * @return The created and persisted token.
     */
    public synchronized CreatedToken createPersisted(String[] scopes, String... groups) {
        return this.createPersisted(List.of(scopes), List.of(groups));
    }

    /**
     * Creates and persists a new token with scopes and groups.
     *
     * @param scopes The scopes assigned to the token.
     * @param groups The groups assigned to the token.
     * @return The created and persisted token.
     */
    public synchronized CreatedToken createPersisted(Collection<String> scopes, String... groups) {
        return this.createPersisted(scopes, List.of(groups));
    }

    /**
     * Creates and persists a new token with scopes and groups.
     *
     * @param scopes The scopes assigned to the token.
     * @param groups The groups assigned to the token.
     * @return The created and persisted token.
     */
    public synchronized CreatedToken createPersisted(Collection<String> scopes, Collection<String> groups) {
        CreatedToken createdToken = create(scopes, groups);
        persist(createdToken.token());
        return createdToken;
    }

    /**
     * Creates a new non-persisted token with the given scopes.
     *
     * @param scopes The scopes assigned to the token.
     * @return The created token wrapper containing token and raw secret.
     */
    public CreatedToken create(String... scopes) {
        return this.create(List.of(scopes));
    }

    /**
     * Creates a new non-persisted token with scopes and groups.
     *
     * @param scopes The scopes assigned to the token.
     * @param groups The groups assigned to the token.
     * @return The created token wrapper containing token and raw secret.
     */
    public CreatedToken create(String[] scopes, String... groups) {
        return this.create(List.of(scopes), List.of(groups));
    }

    /**
     * Creates a new non-persisted token with scopes and groups.
     *
     * @param scopes The scopes assigned to the token.
     * @param groups The groups assigned to the token.
     * @return The created token wrapper containing token and raw secret.
     */
    public CreatedToken create(Collection<String> scopes, String... groups) {
        return this.create(scopes, List.of(groups));
    }

    /**
     * Creates a new non-persisted token with scopes and groups.
     * <p>
     * A unique identifier is generated using a Snowflake algorithm,
     * and a secure random secret is hashed using BCrypt.
     *
     * @param scopes The scopes assigned to the token.
     * @param groups The groups assigned to the token.
     * @return The created token wrapper containing token and raw secret.
     */
    public CreatedToken create(Collection<String> scopes, Collection<String> groups) {
        long id = Snowflake.generate();
        byte[] secret = TokenUtil.newSecureSecret();
        String secretHash = BCrypt.hashpw(secret, BCrypt.gensalt());

        try {
            Token token = new Token(id, secretHash, scopes, OptionalGroup.fromList(groups),
                    new TokenDataContainer());
            CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenCreateEvent(token));
            return new CreatedToken(
                    token,
                    TokenUtil.mergeTokenParts(id, secret)
            );
        } finally {
            PassphraseUtils.erase(secret);
        }
    }

    /**
     * Clears the entire in-memory token cache and triggers
     * a cache revalidation event.
     */
    public synchronized void clearCache() {
        this.tokenCache.clear();
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new RevalidateTokenCacheEvent());
    }

    /**
     * Removes a token from the cache by instance.
     *
     * @param token The token to remove from cache.
     */
    public synchronized void removeCache(Token token) {
        this.removeCache(token.id());
    }

    /**
     * Removes a token from the cache by identifier and triggers
     * a cache revalidation event.
     *
     * @param id The token identifier.
     */
    public synchronized void removeCache(long id) {
        this.tokenCache.remove(id);
        CraftsNetSecurity.getInstance().getListenerRegistry().call(new RevalidateTokenCacheEvent(id));
    }

    /**
     * Returns the global instance of the {@link TokenManager}.
     *
     * @return The active token manager instance.
     */
    public static @NotNull TokenManager getInstance() {
        return CraftsNetSecurityToken.getTokenManager();
    }

    /**
     * Replaces the global {@link TokenManager} instance.
     *
     * @param tokenManager The new token manager instance.
     */
    public static void setInstance(@NotNull TokenManager tokenManager) {
        CraftsNetSecurityToken.setTokenManager(tokenManager);
    }

}
