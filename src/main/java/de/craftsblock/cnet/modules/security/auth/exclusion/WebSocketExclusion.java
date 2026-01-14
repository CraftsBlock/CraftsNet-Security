package de.craftsblock.cnet.modules.security.auth.exclusion;

import de.craftsblock.craftsnet.api.utils.Scheme;
import org.intellij.lang.annotations.RegExp;

import java.util.regex.Pattern;

public record WebSocketExclusion(Scheme scheme, Pattern path) implements Exclusion {

    public WebSocketExclusion(@RegExp String path) {
        this(Scheme.WS, Pattern.compile(path));
    }

}
