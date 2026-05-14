package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.UnmodifiableView;

import java.util.*;

/**
 * Represents a permission group used within the token-based security system.
 * <p>
 * A group defines a named collection of scopes that can be assigned to tokens.
 * These scopes are used to control access rights and authorization checks
 * across the authentication chain.
 * <p>
 * Groups are immutable in their identity (name) but allow modification of their
 * scope collection at runtime.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public final class Group {

    private final @NotNull String name;
    private final @NotNull Collection<String> scopes;
    private final @NotNull
    @UnmodifiableView Collection<String> scopesView;

    /**
     * Creates a new group with the given name and initial scopes.
     *
     * @param name   The unique name of the group
     * @param scopes The initial set of scopes assigned to the group
     */
    public Group(@NotNull String name, @NotNull Collection<String> scopes) {
        this.name = name;
        this.scopes = new ArrayList<>(scopes.stream().distinct().toList());
        this.scopesView = Collections.unmodifiableCollection(this.scopes);
    }

    /**
     * Adds one or more scopes to this group.
     * <p>
     * Duplicate scopes are ignored.
     *
     * @param scopes The scopes to add
     */
    public void addScopes(String... scopes) {
        for (String scope : scopes) {
            if (!hasScope(scope)) {
                this.scopes.add(scope);
            }
        }
    }

    /**
     * Removes one or more scopes from this group.
     *
     * @param scopes The scopes to remove
     */
    public void removeScopes(String... scopes) {
        this.scopes.removeAll(Arrays.asList(scopes));
    }

    /**
     * Checks whether this group contains a specific scope.
     *
     * @param scope The scope to check
     * @return {@code true} if the scope exists, otherwise {@code false}
     */
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /**
     * Checks whether this group contains all provided scopes.
     *
     * @param scopes The scopes to check
     * @return {@code true} if all scopes are present, otherwise {@code false}
     */
    public boolean hasScopes(String... scopes) {
        return this.scopes.containsAll(Arrays.asList(scopes));
    }

    /**
     * Returns the name of this group.
     *
     * @return The group name
     */
    public @NotNull String name() {
        return name;
    }

    /**
     * Returns an unmodifiable view of all scopes assigned to this group.
     *
     * @return The scope collection (read-only view)
     */
    public @NotNull @UnmodifiableView Collection<String> scopes() {
        return scopesView;
    }

    /**
     * Serializes this group into a JSON representation.
     *
     * @return A {@link Json} object containing the group data
     */
    public Json toJson() {
        return Json.empty()
                .set("name", name)
                .set("scopes", scopes);
    }

    /**
     * {@inheritDoc}
     *
     * @param obj {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Group) obj;
        return Objects.equals(this.name, that.name) &&
                Objects.equals(this.scopes, that.scopes);
    }

    /**
     * {@inheritDoc}
     *
     * @return {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Objects.hash(name, scopes);
    }

    /**
     * Deserializes a {@link Group} instance from JSON.
     *
     * @param json The JSON object containing group data
     * @return A reconstructed {@link Group} instance
     */
    public static Group fromJson(Json json) {
        return new Group(json.getString("name"), json.getStringList("scopes"));
    }

}
