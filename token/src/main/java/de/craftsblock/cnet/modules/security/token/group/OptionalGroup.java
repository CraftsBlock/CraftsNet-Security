package de.craftsblock.cnet.modules.security.token.group;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.UnmodifiableView;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

/**
 * Represents a group reference that may or may not be resolved to a persisted
 * {@link Group} instance.
 * <p>
 * This abstraction is used during token processing to represent group names
 * that are attached to a token but may not necessarily exist in the current
 * storage backend.
 * <p>
 * If the group exists in the {@link GroupManager}, the {@link OptionalGroup}
 * will wrap the resolved {@link Group}. Otherwise, it only retains the group
 * name without an associated persistent entity.
 *
 * @param name          the group name identifier
 * @param optionalGroup optional resolved group instance if available
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record OptionalGroup(@NotNull String name, @NotNull Optional<Group> optionalGroup) {

    /**
     * Checks whether this group reference is backed by a persisted group entity.
     *
     * @return {@code true} if the group exists in storage, otherwise {@code false}
     */
    public boolean persisted() {
        return optionalGroup.isPresent();
    }

    /**
     * Returns the resolved group instance if available.
     *
     * @return the {@link Group} instance or {@code null} if not persisted
     */
    public @Nullable Group group() {
        return optionalGroup.orElse(null);
    }

    /**
     * Returns the scopes associated with this group.
     * <p>
     * If the group is not persisted or cannot be resolved, an empty collection
     * is returned.
     *
     * @return an unmodifiable view of the group's scopes or an empty collection
     */
    public @NotNull @UnmodifiableView Collection<String> scopes() {
        Group group = group();
        if (group == null) {
            return Collections.emptyList();
        }

        return group.scopes();
    }

    /**
     * Creates a new {@link OptionalGroup} from a group name and optional resolved group.
     *
     * @param name  the group name
     * @param group the resolved group instance, or {@code null} if not available
     * @return a new {@link OptionalGroup} representing the provided input
     */
    public static OptionalGroup of(@NotNull String name, @Nullable Group group) {
        if (group != null) {
            return new OptionalGroup(group.name(), Optional.of(group));
        }

        return new OptionalGroup(name, Optional.empty());
    }

    /**
     * Resolves a group by name using the {@link GroupManager} and wraps it
     * into an {@link OptionalGroup}.
     *
     * @param name the group name to resolve
     * @return an {@link OptionalGroup} representing the lookup result
     */
    public static OptionalGroup fromString(String name) {
        return of(name, GroupManager.getInstance().get(name));
    }

    /**
     * Converts a collection of group names into a list of {@link OptionalGroup}
     * instances by resolving each name through the {@link GroupManager}.
     *
     * @param names collection of group names
     * @return list of resolved or unresolved {@link OptionalGroup} instances
     */
    public static Collection<OptionalGroup> fromList(Collection<String> names) {
        return names.stream().map(OptionalGroup::fromString).toList();
    }

}
