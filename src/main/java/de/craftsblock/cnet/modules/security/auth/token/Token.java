package de.craftsblock.cnet.modules.security.auth.token;

import de.craftsblock.cnet.modules.security.utils.Entity;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.utils.id.Snowflake;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents a token entity that holds information such as
 * the token ID, hash, and associated permissions.
 * It also provides functionality for validation and serialization.
 *
 * @param id          the unique identifier of the token.
 * @param hash        the hashed value of the token secret.
 * @param permissions a list of {@link TokenPermission}, defining access control rules for the token.
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.2
 * @since 1.0.0-SNAPSHOT
 */
public record Token(long id, String hash, List<TokenPermission> permissions) implements Entity {

    /**
     * Validates if the given secret matches the hashed secret stored in the token.
     *
     * @param secret the secret to be validated.
     * @return {@code true} if the secret matches the hash, {@code false} otherwise.
     */
    public boolean valid(String secret) {
        return BCrypt.checkpw(secret, hash());
    }

    /**
     * Serializes the {@link Token} object into a {@link Json} object,
     * which includes the ID, hash, expiration time, and permission details.
     *
     * @return a {@link Json} object representing the serialized token.
     */
    @Override
    public Json serialize() {
        Json json = Json.empty();
        json.set("id", id);
        json.set("hash", hash);
        json.set("permissions", permissions.stream().map(TokenPermission::serialize).map(Json::getObject).toList());
        return json;
    }

    /**
     * Creates a new {@link  Token} object using a hash.
     * The token ID is generated using the {@link Snowflake} utility.
     * The token will be created with empty permissions by default.
     *
     * @param hash the hashed token secret.
     * @return a new {@link Token} object.
     */
    public static Token of(String hash) {
        return of(Snowflake.generate(), hash, new ArrayList<>());
    }

    /**
     * A private factory method for creating a {@link  Token} object with specified
     * ID, hash, and permissions.
     *
     * @param id          the unique identifier of the token.
     * @param hash        the hashed token secret.
     * @param permissions a list of {@link TokenPermission} associated with this token.
     * @return a new {@link Token} object.
     */
    public static Token of(long id, String hash, List<TokenPermission> permissions) {
        return new Token(id, hash, permissions);
    }
}
