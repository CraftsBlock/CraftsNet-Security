package de.craftsblock.cnet.modules.security.token.util;

import de.craftsblock.craftscore.buffer.BufferUtil;
import de.craftsblock.craftsnet.utils.PassphraseUtils;

import java.nio.charset.StandardCharsets;

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

    private static final String DEFAULT_TOKEN_PREFIX = "cnet_";
    private static final String TOKEN_PART_SEPARATOR = ".";

    private static volatile String TOKEN_PREFIX = DEFAULT_TOKEN_PREFIX;
    private static volatile byte[] TOKEN_PREFIX_BYTES =
            DEFAULT_TOKEN_PREFIX.getBytes(StandardCharsets.UTF_8);

    private static final byte[] TOKEN_PART_SEPARATOR_BYTES =
            TOKEN_PART_SEPARATOR.getBytes(StandardCharsets.UTF_8);

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
        if (secret == null) {
            throw new IllegalArgumentException("Secret must not be null");
        }

        byte[] idBytes = Long.toHexString(id).getBytes(StandardCharsets.UTF_8);
        BufferUtil buffer = BufferUtil.allocate(
                TOKEN_PREFIX_BYTES.length
                        + idBytes.length
                        + TOKEN_PART_SEPARATOR_BYTES.length
                        + secret.length
        );

        try {
            buffer.with(raw -> {
                raw.put(TOKEN_PREFIX_BYTES);
                raw.put(idBytes);
                raw.put(TOKEN_PART_SEPARATOR_BYTES);
                raw.put(secret);
            });

            return buffer.toByteArray();
        } finally {
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
        if (token == null || token.isBlank()) {
            return null;
        }

        String prefix = TOKEN_PREFIX;
        if (!token.startsWith(prefix)) {
            return null;
        }

        String remainder = token.substring(prefix.length());
        if (remainder.isBlank()) {
            return null;
        }

        String[] parts = remainder.split("\\.", 2);
        if (parts.length != 2 || parts[1].isEmpty()) {
            return null;
        }

        try {
            long id = Long.parseLong(parts[0], 16);
            return new TokenParts(
                    prefix,
                    id,
                    parts[1].getBytes(StandardCharsets.UTF_8)
            );
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    /**
     * Updates the global token prefix used for token generation and parsing.
     *
     * @param tokenPrefix the new prefix value
     */
    public synchronized static void setTokenPrefix(String tokenPrefix) {
        if (tokenPrefix == null) {
            throw new IllegalArgumentException("Token prefix must not be null");
        }

        String normalized = tokenPrefix.trim();

        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Token prefix must not be empty");
        }

        if (!normalized.endsWith("_")) {
            normalized += "_";
        }

        TOKEN_PREFIX = normalized;
        TOKEN_PREFIX_BYTES = normalized.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Returns the byte representation of the token part separator.
     *
     * @return the separator bytes used in token serialization
     */
    public synchronized static String getTokenPrefix() {
        return TOKEN_PREFIX;
    }

}
