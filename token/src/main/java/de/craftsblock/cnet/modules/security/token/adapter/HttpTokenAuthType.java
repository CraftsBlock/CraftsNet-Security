package de.craftsblock.cnet.modules.security.token.adapter;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * Defines the possible sources from which an HTTP token can be
 * extracted during authentication.
 * <p>
 * Each type represents a different location within an HTTP request
 * where authentication tokens may be stored, such as headers,
 * cookies, or session attributes.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public enum HttpTokenAuthType {

    /**
     * Token is expected to be provided via an HTTP header,
     * typically the {@code Authorization} header.
     */
    HEADER("Authorization"),

    /**
     * Token is expected to be stored inside an HTTP cookie.
     */
    COOKIE(),

    /**
     * Token is expected to be stored within the HTTP session.
     */
    SESSION(),
    ;

    private final String defaultLocation;

    HttpTokenAuthType() {
        this(null);
    }

    HttpTokenAuthType(String defaultLocation) {
        this.defaultLocation = defaultLocation;
    }

    /**
     * Returns the default location string for this token type.
     * <p>
     * This value represents the default key or name used when
     * retrieving the token from the corresponding source.
     *
     * @return The default location string, or {@code null} if none is defined.
     */
    public @Nullable String getDefaultLocation() {
        return defaultLocation;
    }

    /**
     * Returns the default location, ensuring that it is not {@code null}.
     *
     * @return The non-null default location string.
     * @throws NullPointerException if no default location is defined for this type.
     */
    public @NotNull String ensureDefaultLocation() {
        return Objects.requireNonNull(
                getDefaultLocation(),
                "There is no default location present for the location " + this
        );
    }

    /**
     * Checks whether this token type defines a default location.
     *
     * @return {@code true} if a default location exists, otherwise {@code false}.
     */
    public boolean hasDefaultLocation() {
        return defaultLocation != null;
    }

}
