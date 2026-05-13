package de.craftsblock.cnet.modules.security.auth;

/**
 * Represents the result of an authentication process executed
 * by an authentication adapter or authentication chain.
 * <p>
 * Authentication results can either indicate a successful
 * authentication, a skipped authentication, or a failed
 * authentication attempt.
 * <p>
 * Failure results may additionally contain a reason and a
 * status code that can later be used for response generation.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @see Type
 * @since 1.0.0
 */
public class AuthResult {

    private final Type type;
    private final int code;
    private final String reason;

    /**
     * Creates a new authentication result with the given type.
     *
     * @param type The authentication result type.
     */
    private AuthResult(Type type) {
        this(type, null);
    }

    /**
     * Creates a new authentication result with the given
     * type and failure reason.
     *
     * @param type   The authentication result type.
     * @param reason The failure reason.
     */
    private AuthResult(Type type, String reason) {
        this(type, reason, 400);
    }

    /**
     * Creates a new authentication result with the given
     * type, reason, and response code.
     *
     * @param type   The authentication result type.
     * @param reason The failure reason.
     * @param code   The associated response code.
     */
    private AuthResult(Type type, String reason, int code) {
        this.type = type;
        this.code = code;
        this.reason = reason;
    }

    /**
     * Checks whether the authentication result represents
     * a successful authentication.
     *
     * @return {@code true} if the result type is {@link Type#OK},
     * otherwise {@code false}.
     */
    public boolean isOk() {
        return this.type.equals(Type.OK);
    }

    /**
     * Checks whether the authentication result represents
     * a skipped authentication.
     *
     * @return {@code true} if the result type is {@link Type#SKIP},
     * otherwise {@code false}.
     */
    public boolean isSkip() {
        return this.type.equals(Type.SKIP);
    }

    /**
     * Checks whether the authentication result represents
     * a failed authentication.
     *
     * @return {@code true} if the result type is {@link Type#FAILURE},
     * otherwise {@code false}.
     */
    public boolean isFailure() {
        return this.type.equals(Type.FAILURE);
    }

    /**
     * Retrieves the associated response code.
     *
     * @return The configured response code.
     */
    public int getCode() {
        return code;
    }

    /**
     * Retrieves the failure reason of this authentication result.
     *
     * @return The failure reason, or {@code null} if none exists.
     */
    public String getReason() {
        return reason;
    }

    /**
     * Retrieves the type of this authentication result.
     *
     * @return The authentication result type.
     */
    public Type getType() {
        return type;
    }

    /**
     * Creates a successful authentication result.
     *
     * @return A successful {@link AuthResult}.
     */
    public static AuthResult ok() {
        return new AuthResult(Type.OK);
    }

    /**
     * Creates a skipped authentication result.
     *
     * @return A skipped {@link AuthResult}.
     */
    public static AuthResult skip() {
        return new AuthResult(Type.SKIP);
    }

    /**
     * Creates a failed authentication result without
     * a specific failure reason.
     *
     * @return A failed {@link AuthResult}.
     */
    public static AuthResult failure() {
        return failure(null);
    }

    /**
     * Creates a failed authentication result with
     * the given failure reason.
     *
     * @param reason The failure reason.
     * @return A failed {@link AuthResult}.
     */
    public static AuthResult failure(String reason) {
        return new AuthResult(Type.FAILURE, reason);
    }

    /**
     * Creates a failed authentication result with
     * the given failure reason and response code.
     *
     * @param reason The failure reason.
     * @param code   The associated response code.
     * @return A failed {@link AuthResult}.
     */
    public static AuthResult failure(String reason, int code) {
        return new AuthResult(Type.FAILURE, reason, code);
    }

    /**
     * Represents the possible authentication result states.
     *
     * @author Philipp Maywald
     * @author CraftsBlock
     * @since 1.0.0
     */
    public enum Type {

        /**
         * Indicates that the authentication was successful.
         */
        OK,

        /**
         * Indicates that the authentication was intentionally skipped.
         */
        SKIP,

        /**
         * Indicates that the authentication failed.
         */
        FAILURE,

    }

}
