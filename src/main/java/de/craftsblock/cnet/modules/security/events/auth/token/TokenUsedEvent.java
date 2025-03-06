package de.craftsblock.cnet.modules.security.events.auth.token;

import de.craftsblock.cnet.modules.security.auth.token.Token;
import de.craftsblock.cnet.modules.security.auth.token.adapter.TokenAuthType;
import org.jetbrains.annotations.NotNull;

/**
 * Event triggered when a token is successfully used.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.1
 * @see GenericTokenEvent
 * @see Token
 * @since 1.0.0-SNAPSHOT
 */
public class TokenUsedEvent extends GenericTokenEvent {

    private final TokenAuthType type;

    /**
     * Constructs a new {@link TokenUsedEvent}.
     *
     * @param token The {@link Token} that has been used. Must not be null.
     * @param type  The {@link TokenAuthType} where the {@link Token} was found. Must not be null.
     * @throws NullPointerException If {@code token} is null.
     */
    public TokenUsedEvent(@NotNull Token token, @NotNull TokenAuthType type) {
        super(token);
        this.type = type;
    }

    /**
     * Retrieves the {@link TokenAuthType} where the {@link Token} was
     * found.
     *
     * @return The {@link TokenAuthType} where the {@link Token} was found.
     */
    public @NotNull TokenAuthType getAuthType() {
        return type;
    }

}
