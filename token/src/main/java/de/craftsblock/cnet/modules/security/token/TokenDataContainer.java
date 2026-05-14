package de.craftsblock.cnet.modules.security.token;

import de.craftsblock.craftscore.buffer.BufferUtil;
import de.craftsblock.craftscore.buffer.ObjectSerializer;
import de.craftsblock.craftsnet.utils.reflection.TypeUtils;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A dynamic container for storing arbitrary token-related metadata.
 * <p>
 * This container acts as a flexible key-value store backed by a
 * {@link ConcurrentHashMap}, allowing runtime extension of token
 * information without requiring a fixed schema.
 * <p>
 * Values stored in this container are serialized using
 * {@link ObjectSerializer} for persistence and transmission.
 * When reconstructed, values are deserialized back into their
 * original object form.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class TokenDataContainer extends ConcurrentHashMap<String, Object> {

    /**
     * Creates an empty token data container.
     */
    public TokenDataContainer() {
    }

    /**
     * Reconstructs a token data container from a raw byte array.
     * <p>
     * The byte array is expected to follow the internal serialization
     * format used by {@link #serializeToBytes()}.
     *
     * @param data The serialized container data.
     */
    public TokenDataContainer(byte[] data) {
        BufferUtil buffer = BufferUtil.wrap(data);

        while (buffer.hasRemainingBytes()) {
            String key = buffer.getUtf();
            byte[] value = buffer.getNBytes(buffer.getVarInt());
            this.put(key, ObjectSerializer.deserialize(value));
        }
    }

    /**
     * Reconstructs a token data container from a serialized map
     * representation.
     *
     * @param data A map containing serialized values.
     */
    public TokenDataContainer(Map<String, byte[]> data) {
        data.forEach((key, value) -> this.put(key, ObjectSerializer.deserialize(value)));
    }

    /**
     * Retrieves a typed value from the container.
     *
     * @param key  The key of the value.
     * @param type The expected type of the value.
     * @param <T>  The generic type.
     * @return The stored value cast to the requested type, or {@code null} if absent.
     */
    public <T> T getTyped(@NotNull String key, @NotNull Class<T> type) {
        return this.getOrDefaultTyped(key, type, null);
    }

    /**
     * Retrieves a typed value from the container or returns a fallback value.
     *
     * @param key    The key of the value.
     * @param type   The expected type of the value.
     * @param orElse The fallback value if the key is not present.
     * @param <T>    The generic type.
     * @return The stored value cast to the requested type or the fallback value.
     */
    @SuppressWarnings("unchecked")
    public <T> T getOrDefaultTyped(@NotNull String key, @NotNull Class<T> type, T orElse) {
        if (!containsKey(key)) return orElse;
        return (T) get(key);
    }

    /**
     * Checks whether the value associated with the given key is
     * assignable to the specified type.
     *
     * @param key  The key to check.
     * @param type The expected type.
     * @param <T>  The generic type.
     * @return {@code true} if the stored value matches the type, otherwise {@code false}.
     */
    public <T> boolean isType(@NotNull String key, @NotNull Class<T> type) {
        if (!containsKey(key)) return false;
        return TypeUtils.isAssignable(type, get(key).getClass());
    }

    /**
     * Serializes the container into a compact binary representation.
     * <p>
     * Each entry is written as a UTF key followed by a length-prefixed
     * serialized value.
     *
     * @return The serialized byte array representation of the container.
     */
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

    /**
     * Serializes the container into a map-based binary representation.
     * <p>
     * Each value is individually serialized into a byte array.
     *
     * @return A map containing serialized key-value pairs.
     */
    public Map<String, byte[]> serializeToMap() {
        Map<String, byte[]> serialized = new HashMap<>();
        this.forEach((key, value) -> serialized.put(key, ObjectSerializer.serialize(value)));
        return serialized;
    }

}
