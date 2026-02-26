package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.UnmodifiableView;

import java.util.*;

public final class Group {

    private final @NotNull String name;
    private final @NotNull Collection<String> scopes;
    private final @NotNull
    @UnmodifiableView Collection<String> scopesView;

    public Group(@NotNull String name, @NotNull Collection<String> scopes) {
        this.name = name;
        this.scopes = new ArrayList<>(scopes.stream().distinct().toList());
        this.scopesView = Collections.unmodifiableCollection(this.scopes);
    }

    public void addScopes(String... scopes) {
        for (String scope : scopes) {
            if (!hasScope(scope)) {
                this.scopes.add(scope);
            }
        }
    }

    public void removeScopes(String... scopes) {
        this.scopes.removeAll(Arrays.asList(scopes));
    }

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    public boolean hasScopes(String... scopes) {
        return this.scopes.containsAll(Arrays.asList(scopes));
    }

    public @NotNull String name() {
        return name;
    }

    public @NotNull @UnmodifiableView Collection<String> scopes() {
        return scopesView;
    }

    public Json toJson() {
        return Json.empty()
                .set("name", name)
                .set("scopes", scopes);
    }

    public static Group fromJson(Json json) {
        return new Group(json.getString("name"), json.getStringList("scopes"));
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Group) obj;
        return Objects.equals(this.name, that.name) &&
                Objects.equals(this.scopes, that.scopes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, scopes);
    }


}
