package de.craftsblock.cnet.modules.security.ratelimit;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * The {@link RateLimitIndex} class represents a unique index for rate limiting purposes.
 * It wraps an arbitrary {@link RateLimitIndex#source} object, which serves as the identifier for a rate limit.
 * <p>
 * This class is implemented as a record for immutability and concise representation.
 * </p>
 *
 * @param source The object representing the source of the rate limit.
 *               This could be an IP address, user ID, or any other identifier.
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @see Objects
 * @since 1.0.0-SNAPSHOT
 */
public record RateLimitIndex(@Nullable RateLimitAdapter adapter, @NotNull Object source) {

    /**
     * Compares this {@link RateLimitIndex} with another object for equality.
     * Two {@link RateLimitIndex} instances are considered equal if their {@link #source} fields are equal.
     *
     * @param o The object to compare with this {@link RateLimitIndex}.
     * @return {@code true} if the objects are equal, {@code false} otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RateLimitIndex that = (RateLimitIndex) o;

        if (this.isGlobal()) {
            if (!that.isGlobal() || !Objects.equals(this.adapter(), that.adapter()))
                return false;

        } else if (this.adapter == null || !this.adapter.equals(that.adapter))
            return false;

        return Objects.equals(this.source(), that.source());
    }

    /**
     * Computes the hash code for this {@link RateLimitIndex}.
     * The hash code is derived from the {@link #source} object.
     *
     * @return The hash code of this {@link RateLimitIndex}.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(source);
    }

    /**
     * Checks whether this {@link RateLimitIndex} should be treated globally or
     * per {@link RateLimitAdapter}.
     *
     * @return {@code true} if this {@link RateLimitIndex} should be treated globally,
     * {@code false} otherwise.
     */
    public boolean isGlobal() {
        return this.adapter() == null;
    }

    /**
     * Factory method to create a new global {@link RateLimitIndex} instance,
     * with an instance of {@link Object} as source.
     *
     * @param source The source object to use as the identifier for the rate limit.
     * @return A new {@link RateLimitIndex} instance wrapping the specified {@link RateLimitIndex#source}.
     */
    public static RateLimitIndex of(@NotNull Object source) {
        return new RateLimitIndex(null, source);
    }

    /**
     * Factory method to create a new {@link RateLimitIndex} instance,
     * with an instance of {@link RateLimitAdapter} and an {@link Object} as source.
     *
     * <p>
     * When the {@link RateLimitAdapter} is set to {@code null}, the index should be
     * treated globally.
     * </p>
     *
     * @param adapter The {@link RateLimitAdapter} that created the index.
     * @param source  The source object to use as the identifier for the rate limit.
     * @return A new {@link RateLimitIndex} instance wrapping the specified {@link RateLimitIndex#source}.
     */
    public static RateLimitIndex of(@Nullable RateLimitAdapter adapter, @NotNull Object source) {
        return new RateLimitIndex(adapter, source);
    }

}
