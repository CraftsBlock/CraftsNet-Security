package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.driver.TokenStoreDriver;
import de.craftsblock.cnet.modules.security.token.event.TokenCreateEvent;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.cnet.modules.security.token.util.NewToken;
import de.craftsblock.cnet.modules.security.token.util.TokenParts;
import de.craftsblock.cnet.modules.security.token.util.TokenUtil;
import de.craftsblock.craftscore.cache.Cache;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
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

    public void persist(Token token) {
        CraftsNetSecurity.getStoreDriver().saveToken(token);
    }

    public void delete(Token token) {
        CraftsNetSecurity.getStoreDriver().deleteToken(token);
    }

    public synchronized Token getToken(long id) {
        if (tokenCache.containsKey(id)) {
            return tokenCache.get(id);
        }

        TokenStoreDriver driver = CraftsNetSecurity.getStoreDriver();
        if (!driver.existsToken(id)) {
            return null;
        }

        Token token = driver.loadToken(id);
        tokenCache.put(token.id(), token);
        return token;
    }

    public synchronized Token getValidatedToken(String token) {
        TokenParts parts = TokenUtil.splitToTokenParts(token);
        if (parts == null) {
            return null;
        }

        try {
            Token realToken = getToken(parts.id());
            if (realToken == null || !realToken.validate(parts.secret())) {
                return null;
            }

            return realToken;
        } finally {
            PassphraseUtils.erase(parts.secret());
        }
    }

    public synchronized NewToken newPersistedToken(String... scopes) {
        return this.newPersistedToken(List.of(scopes), Collections.emptyList());
    }

    public synchronized NewToken newPersistedToken(String[] scopes, String... groups) {
        return this.newPersistedToken(List.of(scopes), List.of(groups));
    }

    public synchronized NewToken newPersistedToken(Collection<String> scopes, String... groups) {
        return this.newPersistedToken(scopes, List.of(groups));
    }

    public synchronized NewToken newPersistedToken(Collection<String> scopes, Collection<String> groups) {
        NewToken newToken = newToken(scopes, groups);
        persist(newToken.token());
        return newToken;
    }

    public NewToken newToken(String... scopes) {
        return this.newToken(List.of(scopes));
    }

    public NewToken newToken(String[] scopes, String... groups) {
        return this.newToken(List.of(scopes), List.of(groups));
    }

    public NewToken newToken(Collection<String> scopes, String... groups) {
        return this.newToken(scopes, List.of(groups));
    }

    public NewToken newToken(Collection<String> scopes, Collection<String> groups) {
        long id = Snowflake.generate();
        byte[] secret = TokenUtil.newSecureSecret();
        String secretHash = BCrypt.hashpw(secret, BCrypt.gensalt());

        try {
            Token token = new Token(id, secretHash, scopes, OptionalGroup.fromList(groups),
                    new TokenDataContainer());
            CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenCreateEvent(token));
            return new NewToken(
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

}
