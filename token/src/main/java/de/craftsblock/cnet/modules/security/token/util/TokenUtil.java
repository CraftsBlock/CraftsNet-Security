package de.craftsblock.cnet.modules.security.token.util;

import de.craftsblock.craftscore.buffer.BufferUtil;
import de.craftsblock.craftsnet.utils.PassphraseUtils;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Utility class responsible for token generation, encoding, decoding and
 * structural parsing.
 * <p>
 * Tokens in this system follow a structured format consisting of a prefix,
 * a hexadecimal identifier, and a raw secret separated by a delimiter.
 * <p>
 * This class also provides helpers for secure secret generation and
 * safe in-memory handling of sensitive byte arrays.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
public class TokenUtil {

    private static String TOKEN_PREFIX = "cnet_";
    private static final byte[] TOKEN_PART_SEPARATOR_BYTES = ".".getBytes(StandardCharsets.UTF_8);

    private TokenUtil() {
    }

    /**
     * Generates a new cryptographically secure random secret.
     *
     * @return a newly generated secret byte array
     */
    public static byte[] newSecureSecret() {
        return PassphraseUtils.generateSecure(45, 70, false);
    }

    /**
     * Combines token components into a single serialized token representation.
     * <p>
     * The resulting format is:
     * {@code prefix + hex(id) + "." + secret}
     *
     * @param id     the token identifier
     * @param secret the raw secret bytes
     * @return the serialized token byte array
     */
    public static byte[] mergeTokenParts(long id, byte[] secret) {
        byte[] tokenPrefixBytes = TOKEN_PREFIX.getBytes(StandardCharsets.UTF_8);
        byte[] idBytes = Long.toHexString(id).getBytes(StandardCharsets.UTF_8);

        BufferUtil buffer = BufferUtil.allocate(tokenPrefixBytes.length + idBytes.length
                + TOKEN_PART_SEPARATOR_BYTES.length + secret.length);

        try {
            buffer.with(raw -> {
                raw.put(tokenPrefixBytes);
                raw.put(idBytes);
                raw.put(TOKEN_PART_SEPARATOR_BYTES);
                raw.put(secret);
            });

            return buffer.toByteArray();
        } finally {
            PassphraseUtils.erase(tokenPrefixBytes);
            PassphraseUtils.erase(idBytes);
        }
    }

    /**
     * Splits a serialized token string into its individual components.
     * <p>
     * The method validates the prefix and extracts the identifier and secret
     * parts. If the format is invalid, {@code null} is returned.
     *
     * @param token the serialized token string
     * @return the parsed {@link TokenParts} or {@code null} if invalid
     */
    public static TokenParts splitToTokenParts(String token) {
        if (!token.startsWith(TOKEN_PREFIX)) {
            return null;
        }

        String[] parts = token.replaceFirst("^" + Pattern.quote(TOKEN_PREFIX), "")
                .split("\\.", 2);

        if (parts.length != 2) {
            return null;
        }

        try {
            String id = parts[0];
            long idLong = Long.parseLong(id, 16);
            return new TokenParts(TOKEN_PREFIX.replace("_", ""), idLong, parts[1].getBytes());
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    /**
     * Updates the global token prefix used for token generation and parsing.
     *
     * @param tokenPrefix the new prefix value
     */
    public static void setTokenPrefix(String tokenPrefix) {
        TOKEN_PREFIX = tokenPrefix.replaceAll("_+", "_").trim();

        if (TOKEN_PREFIX.endsWith("_")) return;
        TOKEN_PREFIX += "_";
    }

    /**
     * Returns the currently configured token prefix.
     *
     * @return the active token prefix
     */
    public static String getTokenPrefix() {
        return TOKEN_PREFIX;
    }

    /**
     * Returns the byte representation of the token part separator.
     *
     * @return the separator bytes used in token serialization
     */
    public static byte[] getTokenPartSeparatorBytes() {
        return TOKEN_PART_SEPARATOR_BYTES;
    }

}
