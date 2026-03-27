package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.StoreDriver;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.event.TokenCreateEvent;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.cnet.modules.security.token.util.CreatedToken;
import de.craftsblock.cnet.modules.security.token.util.TokenParts;
import de.craftsblock.cnet.modules.security.token.util.TokenUtil;
import de.craftsblock.craftscore.cache.Cache;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class TokenManager {

    private final Cache<Long, Token> tokenCache;

    public TokenManager() {
        this(25);
    }

    public TokenManager(int cacheSize) {
        this.tokenCache = new Cache<>(cacheSize);
    }

    public synchronized void persist(Token token) {
        StoreDriver.getInstance().saveToken(token);
        tokenCache.put(token.id(), token);
    }

    public synchronized void delete(Token token) {
        this.delete(token.id());
    }

    public synchronized void delete(long id) {
        StoreDriver.getInstance().deleteToken(id);
        removeCache(id);
    }

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

    public synchronized CreatedToken createPersisted(String... scopes) {
        return this.createPersisted(List.of(scopes), Collections.emptyList());
    }

    public synchronized CreatedToken createPersisted(String[] scopes, String... groups) {
        return this.createPersisted(List.of(scopes), List.of(groups));
    }

    public synchronized CreatedToken createPersisted(Collection<String> scopes, String... groups) {
        return this.createPersisted(scopes, List.of(groups));
    }

    public synchronized CreatedToken createPersisted(Collection<String> scopes, Collection<String> groups) {
        CreatedToken createdToken = create(scopes, groups);
        persist(createdToken.token());
        return createdToken;
    }

    public CreatedToken create(String... scopes) {
        return this.create(List.of(scopes));
    }

    public CreatedToken create(String[] scopes, String... groups) {
        return this.create(List.of(scopes), List.of(groups));
    }

    public CreatedToken create(Collection<String> scopes, String... groups) {
        return this.create(scopes, List.of(groups));
    }

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

    public synchronized void clearCache() {
        this.tokenCache.clear();
    }

    public synchronized void removeCache(Token token) {
        this.removeCache(token.id());
    }

    public synchronized void removeCache(long id) {
        this.tokenCache.remove(id);
    }

    public static @NotNull TokenManager getInstance() {
        return CraftsNetSecurity.getTokenManager();
    }

    public static void setInstance(@NotNull TokenManager tokenManager) {
        CraftsNetSecurity.setTokenManager(tokenManager);
    }

}
