package de.craftsblock.cnet.modules.security.token;

import com.google.gson.JsonObject;
import de.craftsblock.cnet.modules.security.token.group.OptionalGroup;
import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.jetbrains.annotations.UnmodifiableView;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.*;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Represents a token used for authentication and authorization
 * within the CraftsNet security module.
 * <p>
 * A token contains a hashed secret, a set of direct scopes, and optional
 * group-based scopes. It also stores additional metadata inside a
 * {@link TokenDataContainer}.
 * <p>
 * Scopes from persisted groups are automatically merged into the effective
 * scope list when accessed.
 *
 * @param id                 The unique identifier of the token.
 * @param hash               The {@link BCrypt} hashed secret of the token.
 * @param scopes             The direct scopes assigned to the token.
 * @param groups             The optional groups associated with the token.
 * @param tokenDataContainer Additional structured token metadata.
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public record Token(long id, @NotNull String hash, @NotNull @UnmodifiableView Collection<String> scopes,
                    @NotNull @UnmodifiableView Collection<OptionalGroup> groups, @NotNull TokenDataContainer tokenDataContainer) {
    /**
     * Creates a new token instance while ensuring that all provided
     * collections are wrapped as unmodifiable views.
     *
     * @param id                 The token identifier.
     * @param hash               The {@link BCrypt} hash of the token secret.
     * @param scopes             The direct scopes of the token.
     * @param groups             The assigned optional groups.
     * @param tokenDataContainer The token metadata container.
     */

    public Token(long id, @NotNull String hash, @NotNull Collection<String> scopes,
                 @NotNull Collection<OptionalGroup> groups, @NotNull TokenDataContainer tokenDataContainer) {
        this.id = id;
        this.hash = hash;
        this.groups = Collections.unmodifiableCollection(groups);
        this.scopes = Collections.unmodifiableCollection(scopes);
        this.tokenDataContainer = tokenDataContainer;
    }

    /**
     * Returns the effective scopes of this token.
     * <p>
     * This includes both directly assigned scopes and all scopes
     * inherited from persisted groups.
     *
     * @return A combined and deduplicated collection of scopes.
     */
    @Override
    public @NotNull @Unmodifiable Collection<String> scopes() {
        return Stream.concat(
                scopes.stream(),
                groups.stream().filter(OptionalGroup::persisted)
                        .flatMap(group -> group.scopes().stream())
        ).distinct().toList();
    }

    /**
     * Returns only the directly assigned scopes of this token,
     * excluding any group-inherited scopes.
     *
     * @return The direct scopes of this token.
     */
    public @NotNull @UnmodifiableView Collection<String> directScopes() {
        return scopes;
    }

    /**
     * Returns the names of all groups assigned to this token.
     *
     * @return A list of group names.
     */
    public Collection<String> groupNames() {
        return groups.stream().map(OptionalGroup::name).toList();
    }

    /**
     * Validates the provided secret against the stored BCrypt hash.
     *
     * @param secret The raw secret to validate.
     * @return {@code true} if the secret matches the stored hash,
     * otherwise {@code false}.
     */
    public boolean validate(byte @NotNull [] secret) {
        return BCrypt.checkpw(secret, hash);
    }

    /**
     * Serializes this token into a JSON representation.
     * <p>
     * The resulting JSON includes the token id, hash, scopes,
     * groups, and the serialized token data container.
     *
     * @return A JSON representation of this token.
     */
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

    /**
     * Deserializes a token from its JSON representation.
     *
     * @param json The JSON object containing the token data.
     * @return The reconstructed {@link Token} instance.
     */
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
        return new Token(
                json.getLong("id"),
                json.getString("hash"),
                json.getStringList("scopes"),
                OptionalGroup.fromList(json.getStringList("groups")),
                tokenDataContainer
        );
    }

}
