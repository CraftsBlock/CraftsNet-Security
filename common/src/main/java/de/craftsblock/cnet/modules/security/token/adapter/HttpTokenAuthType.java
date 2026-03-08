package de.craftsblock.cnet.modules.security.token.adapter;

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

    public String getDefaultLocation() {
        return defaultLocation;
    }

    public boolean hasDefaultLocation() {
        return defaultLocation != null;
    }

}
