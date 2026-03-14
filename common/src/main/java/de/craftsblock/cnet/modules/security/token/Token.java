package de.craftsblock.cnet.modules.security.token;

import com.google.gson.JsonObject;
import de.craftsblock.cnet.modules.security.CraftsNetSecurity;
import de.craftsblock.cnet.modules.security.token.group.GroupManager;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.UnmodifiableView;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.*;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public record Token(long id, @NotNull String hash, @NotNull @UnmodifiableView Collection<String> scopes,
                    @NotNull @UnmodifiableView Collection<OptionalGroup> groups, @NotNull TokenDataContainer tokenDataContainer) {

    public Token(long id, @NotNull String hash, @NotNull Collection<String> scopes,
                 @NotNull Collection<OptionalGroup> groups, @NotNull TokenDataContainer tokenDataContainer) {
        this.id = id;
        this.hash = hash;
        this.groups = Collections.unmodifiableCollection(groups);
        this.scopes = Stream.concat(
                scopes.stream(),
                groups.stream().filter(OptionalGroup::persisted)
                        .flatMap(group -> group.scopes().stream())
        ).distinct().toList();
        this.tokenDataContainer = tokenDataContainer;
    }

    public Collection<String> groupNames() {
        return groups.stream().map(OptionalGroup::name).toList();
    }

    public boolean validate(byte @NotNull [] secret) {
        return BCrypt.checkpw(secret, hash);
    }

    public Json toJson() {
        Json json = Json.empty()
                .set("id", this.id)
                .set("hash", this.hash)
                .set("scopes", this.scopes)
                .set("groups", this.groups.stream().map(OptionalGroup::name).toList());

        Map<String, byte[]> serializedTokenDataContainer = this.tokenDataContainer.serializeToMap();
        serializedTokenDataContainer.forEach((key, data) -> json.set(
                "token_data_container." + key,
                IntStream.range(0, data.length)
                        .mapToObj(i -> data[i])
                        .toList()
        ));

        if (!json.contains("token_data_container")) {
            json.set("token_data_container", new JsonObject());
        }

        return json;
    }

    public static Token fromJson(Json json) {
        Json jsonTokenDataContainer = json.getJson("token_data_container", Json.empty());
        Map<String, byte[]> serializedTokenDataContainer = new HashMap<>();

        jsonTokenDataContainer.keySet().forEach(key -> {
            List<Byte> dataList = (List<Byte>) jsonTokenDataContainer.getByteList(key);
            byte[] data = new byte[dataList.size()];

            for (int i = 0; i < dataList.size(); i++) {
                data[i] = dataList.get(i);
            }

            serializedTokenDataContainer.put(key, data);
        });

        TokenDataContainer tokenDataContainer = new TokenDataContainer(serializedTokenDataContainer);
        GroupManager groupManager = CraftsNetSecurity.getGroupManager();
        return new Token(
                json.getLong("id"),
                json.getString("hash"),
                json.getStringList("scopes"),
                OptionalGroup.fromList(json.getStringList("groups")),
                tokenDataContainer
        );
    }

}
