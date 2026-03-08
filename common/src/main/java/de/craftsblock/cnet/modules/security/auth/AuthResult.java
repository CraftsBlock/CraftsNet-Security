package de.craftsblock.cnet.modules.security.auth;

public class AuthResult {

    private final Type type;
    private final int code;
    private final String reason;

    private AuthResult(Type type) {
        this(type, null);
    }

    private AuthResult(Type type, String reason) {
        this(type, reason, 400);
    }

    private AuthResult(Type type, String reason, int code) {
        this.type = type;
        this.code = code;
        this.reason = reason;
    }

    public boolean isOk() {
        return this.type.equals(Type.OK);
    }

    public boolean isSkip() {
        return this.type.equals(Type.SKIP);
    }

    public boolean isFailure() {
        return this.type.equals(Type.FAILURE);
    }

    public int getCode() {
        return code;
    }

    public String getReason() {
        return reason;
    }

    public Type getType() {
        return type;
    }

    public static AuthResult ok() {
        return new AuthResult(Type.OK);
    }

    public static AuthResult skip() {
        return new AuthResult(Type.SKIP);
    }

    public static AuthResult failure() {
        return failure(null);
    }

    public static AuthResult failure(String reason) {
        return new AuthResult(Type.FAILURE, reason);
    }

    public static AuthResult failure(String reason, int code) {
        return new AuthResult(Type.FAILURE, reason, code);
    }

    public enum Type {

        OK,
        SKIP,
        FAILURE

    }

}
