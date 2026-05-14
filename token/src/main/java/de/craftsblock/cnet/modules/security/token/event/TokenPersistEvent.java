package de.craftsblock.cnet.modules.security.token.event;

import de.craftsblock.cnet.modules.security.token.Token;

/**
 * Event fired when a {@link Token} is persisted to a storage backend.
 * <p>
 * This event is typically triggered before or during writing the token
 * to a persistent store such as a file system or database driver.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class TokenPersistEvent extends TokenEvent {

    /**
     * Creates a new token persistence event.
     *
     * @param token The token being persisted
     */
    public TokenPersistEvent(Token token) {
        super(token);
    }

}
