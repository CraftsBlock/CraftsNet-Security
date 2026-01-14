package de.craftsblock.cnet.modules.security.auth.exclusion;

import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.utils.Scheme;
import org.intellij.lang.annotations.RegExp;

import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Pattern;

public record HttpExclusion(Scheme scheme, Pattern path, HashSet<HttpMethod> methods) implements Exclusion {

    public HttpExclusion(@RegExp String path, HttpMethod... methods) {
        this(Scheme.HTTP, Pattern.compile(path), new HashSet<>(Arrays.asList(HttpMethod.normalize(methods))));
    }

}
