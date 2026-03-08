package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.UnmodifiableView;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

public record OptionalGroup(@NotNull String name, Optional<Group> optionalGroup) {

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

    public static OptionalGroup fromString(String name) {
        return new OptionalGroup(
                name,
                Optional.ofNullable(CraftsNetSecurity.getGroupManager().getGroup(name))
        );
    }

    public static Collection<OptionalGroup> fromList(Collection<String> names) {
        return names.stream().map(OptionalGroup::fromString).toList();
    }

}
