package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.event.TokenCreateEvent;
import de.craftsblock.cnet.modules.security.token.util.NewToken;
import de.craftsblock.cnet.modules.security.token.util.TokenParts;
import de.craftsblock.cnet.modules.security.token.util.TokenUtil;
import de.craftsblock.craftscore.cache.Cache;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.Collection;
import java.util.List;

public class TokenManager {

    private final Cache<Long, Token> tokenCache = new Cache<>(25);

    public void persist(Token token) {
        CraftsNetSecurity.getTokenStoreDriver().save(token);
    }

    public void delete(Token token) {
        CraftsNetSecurity.getTokenStoreDriver().delete(token);
    }

    public Token getToken(long id) {
        if (tokenCache.containsKey(id)) {
            return tokenCache.get(id);
        }

        if (!CraftsNetSecurity.getTokenStoreDriver().exists(id)) {
            return null;
        }

        Token token = CraftsNetSecurity.getTokenStoreDriver().load(id);
        tokenCache.put(token.id(), token);
        return token;
    }

    public Token getValidatedToken(String token) {
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

    public NewToken newPersistedToken(String... scopes) {
        return this.newPersistedToken(List.of(scopes));
    }

    public NewToken newPersistedToken(Collection<String> scopes) {
        NewToken newToken = newToken(scopes);
        persist(newToken.token());
        return newToken;
    }

    public NewToken newToken(String... scopes) {
        return this.newToken(List.of(scopes));
    }

    public NewToken newToken(Collection<String> scopes) {
        long id = Snowflake.generate();
        byte[] secret = TokenUtil.newSecureSecret();
        String secretHash = BCrypt.hashpw(secret, BCrypt.gensalt());

        try {
            Token token = new Token(id, secretHash, scopes, new TokenDataContainer());
            CraftsNetSecurity.getInstance().getListenerRegistry().call(new TokenCreateEvent(token));
            return new NewToken(
                    token,
                    TokenUtil.mergeTokenParts(id, secret)
            );
        } finally {
            PassphraseUtils.erase(secret);
        }
    }

    public void clearCache() {
        this.tokenCache.clear();
    }

}
