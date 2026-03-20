package de.craftsblock.cnet.modules.security.token.adapter;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public enum HttpTokenAuthType {

    HEADER("Authorization"),
    COOKIE(),
    SESSION(),
    ;

    private final String defaultLocation;

    HttpTokenAuthType() {
        this(null);
    }

    HttpTokenAuthType(String defaultLocation) {
        this.defaultLocation = defaultLocation;
    }

    public @Nullable String getDefaultLocation() {
        return defaultLocation;
    }

    public @NotNull String ensureDefaultLocation() {
        return Objects.requireNonNull(
                getDefaultLocation(),
                "There is no default location present for the location " + this
        );
    }

    public boolean hasDefaultLocation() {
        return defaultLocation != null;
    }

}
