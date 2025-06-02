package de.craftsblock.cnet.modules.security.auth.token;

import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.token.driver.storage.TokenStorageDriver;
import de.craftsblock.cnet.modules.security.events.auth.token.TokenCreateEvent;
import de.craftsblock.cnet.modules.security.events.auth.token.TokenRevokeEvent;
import de.craftsblock.cnet.modules.security.utils.Manager;
import de.craftsblock.craftscore.annotations.Experimental;
import de.craftsblock.craftsnet.api.http.HttpMethod;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Manages a collection of authentication tokens, providing functionality to register, unregister, save,
 * and generate tokens with associated permissions. It extends {@link ConcurrentHashMap} to store tokens
 * by their unique IDs and implements the {@link Manager} interface for managing token-related operations.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.3.1
 * @since 1.0.0-SNAPSHOT
 */
public final class TokenManager extends ConcurrentHashMap<Long, Token> implements Manager {

    private static TokenStorageDriver DRIVER;

    private static String TOKEN_PREFIX = "cnet_";
    private static String TOKEN_PREFIX_DELIMITER = "_";

    /**
     * Sets the storage driver to be used for persisting tokens and loads all tokens from it.
     * <p>
     * Existing tokens in the manager will be cleared and replaced with the loaded ones.
     * </p>
     *
     * @param driver The {@link TokenStorageDriver} to be set and used for token persistence.
     */
    @Experimental
    @ApiStatus.Experimental
    public static void setDriver(@NotNull TokenStorageDriver driver) {
        TokenManager.DRIVER = driver;

        TokenManager manager = CNetSecurity.getTokenManager();
        if (manager == null) return;

        manager.clear();
        driver.loadAll().forEach(token -> manager.put(token.id(), token));
    }

    /**
     * Retrieves the currently set {@link TokenStorageDriver} used for token persistence.
     *
     * @return The current {@link TokenStorageDriver}, or {@code null} if none is set.
     */
    @Experimental
    @ApiStatus.Experimental
    public static @Nullable TokenStorageDriver getDriver() {
        return DRIVER;
    }

    /**
     * Sets the prefix used when generating token strings.
     *
     * @param tokenPrefix The prefix string to be used for tokens.
     */
    @Experimental
    @ApiStatus.Experimental
    public static void setTokenPrefix(String tokenPrefix) {
        TOKEN_PREFIX = tokenPrefix.replaceAll(TOKEN_PREFIX_DELIMITER + "+", TOKEN_PREFIX_DELIMITER).trim();

        if (TOKEN_PREFIX.endsWith(TOKEN_PREFIX_DELIMITER)) return;
        TOKEN_PREFIX += TOKEN_PREFIX_DELIMITER;
    }

    /**
     * Retrieves the currently configured token prefix.
     *
     * @return The token prefix as a string.
     */
    @Experimental
    @ApiStatus.Experimental
    public static String getTokenPrefix() {
        return TOKEN_PREFIX;
    }

    /**
     * Sets the delimiter used to split token components.
     * <p>
     * The delimiter will be quoted to ensure it is used correctly in regular expressions.
     * </p>
     *
     * @param tokenPrefixDelimiter The delimiter to be used in token formatting.
     */
    @Experimental
    @ApiStatus.Experimental
    public static void setTokenPrefixDelimiter(String tokenPrefixDelimiter) {
        TOKEN_PREFIX_DELIMITER = Pattern.quote(tokenPrefixDelimiter);
    }

    /**
     * Retrieves the currently configured token prefix delimiter.
     *
     * @return The token prefix delimiter as a string.
     */
    @Experimental
    @ApiStatus.Experimental
    public static String getTokenPrefixDelimiter() {
        return TOKEN_PREFIX_DELIMITER;
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
        DRIVER.delete(token);
    }

    /**
     * Saves the current tokens in the token manager to the driver.
     */
    public void save() {
        DRIVER.save(this.values());
    }

    /**
     * Generates a new token with the provided permissions, creates a random secret,
     * hashes the secret using BCrypt, and associates the permissions with the token.
     *
     * @param permissions An array of {@link TokenPermission} to be associated with the token.
     * @return A {@link Map.Entry} containing the plain text secret (as the key) and the generated {@link Token} (as the value).
     */
    public Map.Entry<byte[], Token> generateToken(TokenPermission... permissions) {
        return generateToken(Arrays.asList(permissions));
    }

    /**
     * Generates a new token with the provided list of permissions, creates a random secret,
     * hashes the secret using BCrypt, and associates the permissions with the token.
     *
     * @param permissions A list of {@link TokenPermission} to be associated with the token.
     * @return A {@link Map.Entry} containing the plain text secret (as the key) and the generated {@link Token} (as the value).
     */
    public Map.Entry<byte[], Token> generateToken(List<TokenPermission> permissions) {
        byte[] secret = this.generateTokenSecret();
        String hash = BCrypt.hashpw(secret, BCrypt.gensalt());

        Token token = Token.of(hash);
        token.permissions().addAll(permissions);
        registerToken(token);

        Map.Entry<byte[], Token> tokenEntry = Map.entry(generatePlainToken(token.id(), secret), token);
        PassphraseUtils.erase(secret);
        return tokenEntry;
    }

    /**
     * Generates a plain token in the format {@code cnet_<hex(id)>[secret]}.
     * <p>
     * The token is composed of a UTF-8 prefix, the hexadecimal representation of the ID, and the raw secret bytes.
     * </p>
     *
     * @param id     The identifier to embed in the token, encoded as hexadecimal.
     * @param secret The secret byte array to include in the token; must not be null.
     * @return A byte array representing the constructed token.
     * @throws RuntimeException If an I/O error occurs during token generation.
     */
    public byte[] generatePlainToken(long id, byte[] secret) {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.write(TOKEN_PREFIX.getBytes(StandardCharsets.UTF_8));
            stream.write(Long.toHexString(id).getBytes(StandardCharsets.UTF_8));
            stream.write(secret);

            return stream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Could not write plain token!", e);
        }
    }

    /**
     * Generates a secure random byte array to be used as a token secret.
     * <p>
     * The generated secret is between 45 and 70 bytes long and excludes special characters.
     * </p>
     *
     * @return A securely generated byte array to be used as a token secret.
     */
    public byte[] generateTokenSecret() {
        return PassphraseUtils.generateSecure(45, 70, false);
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
        String[] parts = token.split(TOKEN_PREFIX_DELIMITER);
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

        String[] parts = token.split(TOKEN_PREFIX_DELIMITER);
        if (parts.length < 2 || parts[1].length() < 16) return null;

        if (!TOKEN_PREFIX.equalsIgnoreCase(parts[0])) return null;

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
            throw new RuntimeException("Could not verify the token", e);
        }
    }

}
