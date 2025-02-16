package de.craftsblock.cnet.modules.security.auth.token;

import com.google.gson.JsonElement;
import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.events.auth.token.TokenCreateEvent;
import de.craftsblock.cnet.modules.security.events.auth.token.TokenRevokeEvent;
import de.craftsblock.cnet.modules.security.utils.Manager;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.utils.Utils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages a collection of authentication tokens, providing functionality to register, unregister, save,
 * and generate tokens with associated permissions. It extends {@link ConcurrentHashMap} to store tokens
 * by their unique IDs and implements the {@link Manager} interface for managing token-related operations.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @since 1.0.0-SNAPSHOT
 */
public final class TokenManager extends ConcurrentHashMap<Long, Token> implements Manager {

    private final File saveFile;

    /**
     * Constructs a new {@link TokenManager} and loads tokens from the save file.
     * The tokens are stored in a JSON file located in the addon's data folder.
     * If the file contains a valid json array, tokens are deserialized and loaded into the manager.
     */
    public TokenManager() {
        saveFile = new File(CNetSecurity.getAddonEntrypoint().getDataFolder(), "tokens.json");
        Json json = JsonParser.parse(saveFile);
        if (!json.getObject().isJsonArray()) return;

        for (JsonElement element : json.getObject().getAsJsonArray()) {
            Token token = Token.of(JsonParser.parse(element));
            this.put(token.id(), token);
        }
    }

    /**
     * Registers a new token by adding it to the token manager.
     *
     * @param token The {@link Token} to be registered.
     */
    public void registerToken(Token token) {
        try {
            TokenCreateEvent event = new TokenCreateEvent(token);
            if (event.isCancelled()) {
                CNetSecurity.getLogger().debug("Token creation of token " + token.id() + " cancelled!");
                return;
            }

            CNetSecurity.callEvent(event);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        this.put(token.id(), token);
    }

    /**
     * Unregisters a token by removing it from the token manager.
     *
     * @param token The {@link Token} to be unregistered.
     */
    public void unregisterToken(Token token) {
        try {
            TokenRevokeEvent event = new TokenRevokeEvent(token);
            if (event.isCancelled()) {
                CNetSecurity.getLogger().debug("Token revokation for token " + token.id() + " cancelled!");
                return;
            }

            CNetSecurity.callEvent(event);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        this.remove(token.id());
    }

    /**
     * Saves the current tokens in the token manager to a json file. The file is stored
     * in the addon's data folder. All tokens are serialized and saved as a json array.
     */
    public void save() {
        Json json = Json.empty();
        this.values().forEach(token -> json.set("$new", token.serialize()));
        json.save(saveFile);
    }

    /**
     * Generates a new token with the provided permissions, creates a random secret,
     * hashes the secret using BCrypt, and associates the permissions with the token.
     *
     * @param permissions An array of {@link TokenPermission} to be associated with the token.
     * @return A {@link Map.Entry} containing the plain text secret (as the key) and the generated {@link Token} (as the value).
     */
    public Map.Entry<String, Token> generateToken(TokenPermission... permissions) {
        return generateToken(Arrays.asList(permissions));
    }

    /**
     * Generates a new token with the provided list of permissions, creates a random secret,
     * hashes the secret using BCrypt, and associates the permissions with the token.
     *
     * @param permissions A list of {@link TokenPermission} to be associated with the token.
     * @return A {@link Map.Entry} containing the plain text secret (as the key) and the generated {@link Token} (as the value).
     */
    public Map.Entry<String, Token> generateToken(List<TokenPermission> permissions) {
        try {
            String secret = Utils.secureRandomPassphrase(45, 70, false);
            String hash = BCrypt.hashpw(secret, BCrypt.gensalt());

            Token token = Token.of(hash);
            token.permissions().addAll(permissions);
            registerToken(token);

            return Map.entry("cnet_" + Long.toHexString(token.id()) + secret, token);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves a {@link Token} based on the given token string.
     * The token string is expected to contain an identifier in hexadecimal format.
     * If the token is invalid or cannot be parsed, this method returns {@code null}.
     *
     * @param token The token string to be parsed.
     * @return The corresponding {@link Token} if found, otherwise {@code null}.
     */
    public @Nullable Token getToken(@NotNull String token) {
        // Split the token into parts
        String[] parts = token.split("_");
        if (parts.length == 0) return null;

        String part = parts.length >= 2 ? parts[1] : parts[0];
        if (part.length() < 16) return null;

        try {
            long id = Long.parseLong(part.substring(0, 16), 16);
            return CNetSecurity.getTokenManager().get(id);
        } catch (NumberFormatException | IllegalStateException ignored) {
            return null;
        }
    }

    /**
     * Retrieves and validates a {@link Token} for a given request.
     * This method first attempts to retrieve the token using {@link #getToken(String)}.
     * If the token exists, it verifies the token's validity based on the provided url, domain, http method, and secret.
     *
     * @param url    The requested URL.
     * @param domain The domain from which the request originates.
     * @param method The HTTP method of the request.
     * @param token  The token string to be validated.
     * @return The validated {@link Token} if authentication is successful, otherwise {@code null}.
     */
    public @Nullable Token getValidatedToken(@NotNull String url, @NotNull String domain, @NotNull HttpMethod method, @NotNull String token) {
        Token realToken = getToken(token);
        if (realToken == null) return null;

        String[] parts = token.split("_");
        if (parts.length < 2 || parts[1].length() < 16) return null;

        String secret = parts[1].substring(16);
        return isTokenValid(url, domain, method, secret, realToken) ? realToken : null;
    }

    /**
     * Validates whether a given {@link Token} is authorized for the requested action.
     * The token is verified using its hashed secret and checked for permission against the specified http method, domain, and url.
     *
     * @param url    The requested URL.
     * @param domain The domain from which the request originates.
     * @param method The HTTP method of the request.
     * @param secret The secret extracted from the token for authentication.
     * @param token  The {@link Token} object to be validated.
     * @return {@code true} if the token is valid and authorized, otherwise {@code false}.
     */
    public boolean isTokenValid(@NotNull String url, @NotNull String domain, @NotNull HttpMethod method, @NotNull String secret, Token token) {
        if (token == null || secret.isBlank()) return false;

        try {
            // Extract the secret from the token and verify it
            if (!BCrypt.checkpw(secret, token.hash())) return false;

            // Check the token permissions
            return token.permissions().stream()
                    .anyMatch(permission -> permission.isHttpMethodAllowed(method)
                            && permission.isDomainAllowed(domain)
                            && permission.isPathAllowed(url));
        } catch (Exception e) {
            CNetSecurity.getAddonEntrypoint().logger().error(e, "Failed to verify the api token!");
            return false;
        }
    }

}
