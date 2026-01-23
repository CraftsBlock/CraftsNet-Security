package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.util.NewToken;
import de.craftsblock.cnet.modules.security.token.util.TokenParts;
import de.craftsblock.cnet.modules.security.token.util.TokenUtil;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.Collection;
import java.util.List;

public class TokenManager {

    public void persist(Token token) {
        CraftsNetSecurity.getTokenStoreDriver().save(token);
    }

    public void delete(Token token) {
        CraftsNetSecurity.getTokenStoreDriver().delete(token);
    }

    public Token getToken(String token) {
        TokenParts parts = TokenUtil.splitToTokenParts(token);
        if (parts == null) {
            return null;
        }

        try {
            if (!CraftsNetSecurity.getTokenStoreDriver().exists(parts.id())) {
                return null;
            }

            Token realToken = CraftsNetSecurity.getTokenStoreDriver().load(parts.id());
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
            return new NewToken(
                    new Token(id, secretHash, scopes, new TokenDataContainer()),
                    TokenUtil.mergeTokenParts(id, secret)
            );
        } finally {
            PassphraseUtils.erase(secret);
        }
    }

}
