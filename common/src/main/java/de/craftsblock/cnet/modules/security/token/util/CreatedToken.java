package de.craftsblock.cnet.modules.security.token.util;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftsnet.utils.PassphraseUtils;

public record CreatedToken(Token token, byte[] plain) implements AutoCloseable {

    public String plainStringify() {
        return PassphraseUtils.stringify(plain);
    }

    @Override
    public void close() {
        PassphraseUtils.erase(plain);
    }

}
