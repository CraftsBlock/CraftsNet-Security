package de.craftsblock.cnet.modules.security.auth.token.driver.storage;

import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.token.Token;
import de.craftsblock.cnet.modules.security.auth.token.TokenPermission;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.api.http.HttpMethod;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A file-based implementation of {@link TokenStorageDriver} that serializes tokens
 * and stores them in a json file.
 *
 * <p>This implementation is useful for lightweight deployments where a database
 * is not available or necessary.</p>
 *
 * <p>The file is synchronized during read/write operations to ensure thread safety.</p>
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @see Json
 * @see TokenStorageDriver
 * @since 1.0.0-SNAPSHOT
 */
public class FileTokenStorageDriver extends TokenStorageDriver {

    private final Path saveFile;

    /**
     * Constructs a {@link FileTokenStorageDriver} that stores tokens in the default {@code tokens.json}
     * file within the plugin's data folder.
     */
    public FileTokenStorageDriver() {
        this(CNetSecurity.getAddonEntrypoint().getDataFolder().toPath().resolve("tokens.json"));
    }

    /**
     * Constructs a {@link FileTokenStorageDriver} that stores tokens in the specified file.
     *
     * @param saveFile The path to the file where tokens will be stored.
     */
    public FileTokenStorageDriver(Path saveFile) {
        if (!Files.isRegularFile(saveFile) && !Files.isSymbolicLink(saveFile))
            throw new IllegalArgumentException("");

        this.saveFile = saveFile;
    }

    /**
     * Saves the given collection of tokens to the configured json file.
     * <p>
     * Each token is serialized to json and stored under its id as the key.
     * The write operation is synchronized to avoid concurrent access issues.
     *
     * @param tokens The tokens to save.
     */
    @Override
    public void save(Collection<Token> tokens) {
        Json json = Json.empty();
        tokens.forEach(token -> json.set(String.valueOf(token.id()), token.serialize()));

        synchronizedSave(json);
    }

    /**
     * Loads all tokens from the json file.
     * <p>
     * Parses each json object and reconstructs the {@link Token} and associated {@link TokenPermission}s.
     * The read operation is synchronized to ensure thread safety.
     *
     * @return A collection of all loaded tokens, or an empty list if the file is empty or invalid.
     */
    @Override
    public Collection<Token> loadAll() {
        Json json = synchronizedRead();
        if (!json.getObject().isJsonObject()) return List.of();

        return json.values().stream()
                .map(JsonParser::parse)
                .map(this::createTokenFromJson)
                .toList();
    }

    /**
     * Synchronously reads the contents of the json file and parses it into a {@link Json} object.
     *
     * @return The parsed {@link Json} object from the file.
     */
    private Json synchronizedRead() {
        synchronized (saveFile) {
            return JsonParser.parse(saveFile);
        }
    }

    /**
     * Synchronously writes the given {@link Json} object to the file.
     *
     * @param json The {@link Json} data to write to the file.
     */
    private void synchronizedSave(Json json) {
        synchronized (saveFile) {
            json.save(saveFile);
        }
    }

    /**
     * Returns the file path used for saving and loading token data.
     *
     * @return The path to the save file.
     */
    public Path getSaveFile() {
        return saveFile;
    }

    /**
     * Constructs a {@link Token} from the given json object.
     * <p>
     * Parses the token id, hash, and all associated permissions from the nested json structure.
     *
     * @param json The json object representing a token.
     * @return The constructed {@link Token}.
     */
    private Token createTokenFromJson(Json json) {
        return Token.of(json.getLong("id"), json.getString("hash"),
                new ArrayList<>(json.getJsonList("permissions").stream().map(this::createTokenPermissionFromJson).toList()));
    }

    /**
     * Constructs a {@link TokenPermission} from the given json object.
     * <p>
     * If the permission does not contain an "id" field, a new id is generated using {@link Snowflake}
     * to maintain compatibility with older formats.
     *
     * @param json The json object representing a permission.
     * @return The constructed {@link TokenPermission}.
     */
    private TokenPermission createTokenPermissionFromJson(Json json) {
        // Required for backwards compatibility, as the old token permissions do not have an id
        long id = json.contains("id") ? json.getLong("id") : Snowflake.generate();

        return TokenPermission.of(
                id, json.getString("path"), json.getString("domain"),
                json.getStringList("methods").stream().map(HttpMethod::parse).toArray(HttpMethod[]::new)
        );
    }

}
