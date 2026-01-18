package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.craftscore.buffer.BufferUtil;
import de.craftsblock.craftscore.buffer.ObjectSerializer;
import de.craftsblock.craftsnet.utils.reflection.TypeUtils;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TokenDataContainer extends ConcurrentHashMap<String, Object> {

    public TokenDataContainer() {
    }

    public TokenDataContainer(byte[] data) {
        BufferUtil buffer = BufferUtil.wrap(data);

        while (buffer.hasRemainingBytes()) {
            String key = buffer.getUtf();
            byte[] value = buffer.getNBytes(buffer.getVarInt());
            this.put(key, ObjectSerializer.deserialize(value));
        }
    }

    public TokenDataContainer(Map<String, byte[]> data) {
        data.forEach((key, value) -> this.put(key, ObjectSerializer.deserialize(value)));
    }

    public <T> T getTyped(@NotNull String key, @NotNull Class<T> type) {
        return this.getOrDefaultTyped(key, type, null);
    }

    @SuppressWarnings("unchecked")
    public <T> T getOrDefaultTyped(@NotNull String key, @NotNull Class<T> type, T orElse) {
        if (!containsKey(key)) return orElse;
        return (T) get(key);
    }

    public <T> boolean isType(@NotNull String key, @NotNull Class<T> type) {
        if (!containsKey(key)) return false;
        return TypeUtils.isAssignable(type, get(key).getClass());
    }

    public byte[] serializeToBytes() {
        BufferUtil buffer = BufferUtil.allocate(0);

        this.forEach((key, value) -> {
            byte[] serialized = ObjectSerializer.serialize(value);

            buffer.ensure(8 + key.getBytes(StandardCharsets.UTF_8).length + serialized.length)
                    .putUtf(key)
                    .putVarInt(serialized.length)
                    .with(raw -> raw.put(serialized));
        });

        return buffer.trim().toByteArray();
    }

    public Map<String, byte[]> serializeToMap() {
        Map<String, byte[]> serialized = new HashMap<>();
        this.forEach((key, value) -> serialized.put(key, ObjectSerializer.serialize(value)));
        return serialized;
    }

}
