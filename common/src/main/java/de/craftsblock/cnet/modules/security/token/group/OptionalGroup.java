package de.craftsblock.cnet.modules.security.token.group;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.UnmodifiableView;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

public record OptionalGroup(@NotNull String name, @NotNull Optional<Group> optionalGroup) {

    public boolean persisted() {
        return optionalGroup.isPresent();
    }

    public @Nullable Group group() {
        return optionalGroup.orElse(null);
    }

    public @NotNull @UnmodifiableView Collection<String> scopes() {
        Group group = group();
        if (group == null) {
            return Collections.emptyList();
        }

        return group.scopes();
    }

    public static OptionalGroup of(@NotNull String name, @Nullable Group group) {
        if (group != null) {
            return new OptionalGroup(group.name(), Optional.of(group));
        }

        return new OptionalGroup(name, Optional.empty());
    }

    public static OptionalGroup fromString(String name) {
        return of(name, GroupManager.getInstance().get(name));
    }

    public static Collection<OptionalGroup> fromList(Collection<String> names) {
        return names.stream().map(OptionalGroup::fromString).toList();
    }

}
