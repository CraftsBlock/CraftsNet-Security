package de.craftsblock.cnet.modules.security.token.util;

import de.craftsblock.cnet.modules.security.token.Token;
import de.craftsblock.craftsnet.utils.PassphraseUtils;

/**
 * Wrapper representing a freshly created authentication token including its
 * associated {@link Token} model and the generated plain-text secret.
 * <p>
 * This object is typically returned when a token is created and persisted,
 * allowing the caller to present the plain secret to the user once.
 * <p>
 * Since the plain secret is sensitive information, this record implements
 * {@link AutoCloseable} to allow explicit secure cleanup of the underlying
 * byte array.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record CreatedToken(Token token, byte[] plain) implements AutoCloseable {

    /**
     * Converts the raw plain token bytes into a human-readable string
     * representation suitable for transmission or display.
     *
     * @return the token secret as a string
     */
    public String plainStringify() {
        return PassphraseUtils.stringify(plain);
    }

    /**
     * Securely erases the stored plain-text token secret from memory.
     * <p>
     * This should be called immediately after the token has been displayed
     * or transmitted to ensure sensitive data is not retained longer than necessary.
     */
    @Override
    public void close() {
        PassphraseUtils.erase(plain);
    }

}
