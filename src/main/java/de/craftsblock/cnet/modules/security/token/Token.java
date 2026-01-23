package de.craftsblock.cnet.modules.security.token;

import com.google.gson.JsonObject;
import de.craftsblock.craftscore.json.Json;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.UnmodifiableView;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.*;
import java.util.stream.IntStream;

public record Token(long id, @NotNull String hash, @NotNull Collection<String> scopes, @NotNull TokenDataContainer tokenDataContainer) {

    public Token(long id, @NotNull String hash, @NotNull Collection<String> scopes, @NotNull TokenDataContainer tokenDataContainer) {
        this.id = id;
        this.hash = hash;
        this.scopes = Collections.unmodifiableCollection(scopes);
        this.tokenDataContainer = tokenDataContainer;
    }

    @Override
    public @NotNull @UnmodifiableView Collection<String> scopes() {
        return scopes;
    }

    public boolean validate(byte @NotNull [] secret) {
        return BCrypt.checkpw(secret, hash);
    }

    public Json toJson() {
        Json json = Json.empty()
                .set("id", this.id)
                .set("hash", this.hash)
                .set("scopes", this.scopes);

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
        return new Token(
                json.getLong("id"),
                json.getString("hash"),
                json.getStringList("scopes"),
                tokenDataContainer
        );
    }

}
