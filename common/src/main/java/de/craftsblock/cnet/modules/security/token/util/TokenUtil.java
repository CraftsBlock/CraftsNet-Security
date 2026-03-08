package de.craftsblock.cnet.modules.security.token.util;

import de.craftsblock.craftscore.buffer.BufferUtil;
import de.craftsblock.craftsnet.utils.PassphraseUtils;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public class TokenUtil {

    private static String TOKEN_PREFIX = "cnet_";
    private static final byte[] TOKEN_PART_SEPARATOR_BYTES = ".".getBytes(StandardCharsets.UTF_8);

    private TokenUtil() {
    }

    public static byte[] newSecureSecret() {
        return PassphraseUtils.generateSecure(45, 70, false);
    }

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

    public static void setTokenPrefix(String tokenPrefix) {
        TOKEN_PREFIX = tokenPrefix.replaceAll("_+", "_").trim();

        if (TOKEN_PREFIX.endsWith("_")) return;
        TOKEN_PREFIX += "_";
    }

    public static String getTokenPrefix() {
        return TOKEN_PREFIX;
    }

    public static byte[] getTokenPartSeparatorBytes() {
        return TOKEN_PART_SEPARATOR_BYTES;
    }

}
