package de.craftsblock.cnet.modules.security.auth.exclusion;

import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.api.utils.Scheme;
import org.intellij.lang.annotations.RegExp;

import java.util.*;
import java.util.regex.Matcher;

public final class Exclusions {

    private final Map<Scheme, Collection<Exclusion>> exclusions = new EnumMap<>(Scheme.class);

    public Exclusions http(@RegExp String path, HttpMethod... methods) {
        Collection<Exclusion> httpExclusions = exclusions.computeIfAbsent(Scheme.HTTP, s -> new ArrayList<>());

        synchronized (httpExclusions) {
            for (Exclusion exclusion : httpExclusions) {
                if (!(exclusion instanceof HttpExclusion httpExclusion)) {
                    throw new IllegalStateException("Found a non http exclusion "
                            + exclusion.getClass().getName() + " in the http list!");
                }

                if (exclusion.path().pattern().equals(path) &&
                        httpExclusion.methods().containsAll(Arrays.asList(HttpMethod.normalize(methods)))) {
                    return this;
                }
            }

            httpExclusions.add(new HttpExclusion(path, methods));
        }

        return this;
    }

    public boolean isHttpExcluded(String path, HttpMethod method) {
        Collection<Exclusion> httpExclusions = exclusions.get(Scheme.HTTP);
        if (httpExclusions == null) {
            return false;
        }

        synchronized (httpExclusions) {
            for (Exclusion exclusion : httpExclusions) {
                if (!(exclusion instanceof HttpExclusion httpExclusion)) {
                    throw new IllegalStateException("Found a non http exclusion "
                            + exclusion.getClass().getName() + " in the http list!");
                }

                Matcher matcher = exclusion.path().matcher(path);
                if (!matcher.matches()) {
                    continue;
                }

                if (httpExclusion.methods().contains(method)) {
                    return true;
                }
            }
        }

        return false;
    }

    public Exclusions webSocket(@RegExp String path) {
        Collection<Exclusion> webSocketExclusions = exclusions.computeIfAbsent(Scheme.WS, s -> new ArrayList<>());

        synchronized (webSocketExclusions) {
            for (Exclusion exclusion : webSocketExclusions) {
                if (!(exclusion instanceof WebSocketExclusion)) {
                    throw new IllegalStateException("Found a non web socket exclusion "
                            + exclusion.getClass().getName() + " in the web socket list!");
                }

                if (exclusion.path().pattern().equals(path)) {
                    return this;
                }
            }

            webSocketExclusions.add(new WebSocketExclusion(path));
        }

        return this;
    }

    public boolean isWebSocketExcluded(String path) {
        Collection<Exclusion> httpExclusions = exclusions.get(Scheme.WS);
        if (httpExclusions == null) {
            return false;
        }

        synchronized (httpExclusions) {
            for (Exclusion exclusion : httpExclusions) {
                if (!(exclusion instanceof WebSocketExclusion)) {
                    throw new IllegalStateException("Found a non web socket exclusion "
                            + exclusion.getClass().getName() + " in the web socket list!");
                }

                Matcher matcher = exclusion.path().matcher(path);
                if (matcher.matches()) {
                    return true;
                }
            }
        }

        return false;
    }

}
