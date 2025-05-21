package de.craftsblock.cnet.modules.security.auth;

/**
 * The {@link AuthResult} class represents the outcome of an authentication process.
 * It provides information about whether the authentication was successful or cancelled,
 * and if cancelled, it holds a reason for the cancellation.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.1
 * @since 1.0.0-SNAPSHOT
 */
public class AuthResult {

    private boolean success = true;
    private int code = 401;
    private String cancelReason = "";

    /**
     * Creates a new {@link AuthResult} instance with a default success state of {@code true}.
     */
    public AuthResult() {
    }

    /**
     * Cancels the authentication, setting the success state to {@code false}.
     */
    public void cancel() {
        this.success = false;
    }

    /**
     * Cancels the authentication with a specific reason.
     *
     * @param reason The reason for cancellation, providing context for the failure.
     */
    public void cancel(String reason) {
        this.cancel(403, reason);
    }

    /**
     * Cancels the authentication with a specific reason.
     *
     * @param reason The reason for cancellation, providing context for the failure.
     */
    public void cancel(int code, String reason) {
        this.cancel();
        this.cancelReason = reason;
        this.code = code;
    }

    /**
     * Returns whether the authentication was successful or not.
     *
     * @return {@code true} if the authentication was successful, {@code false} otherwise.
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Returns whether the authentication process was cancelled.
     *
     * @return {@code true} if the process was cancelled, {@code false} otherwise.
     */
    public boolean isCancelled() {
        return !success;
    }

    /**
     * Returns the reason for cancelling the authentication process.
     * If the authentication was successful, this will return an empty string.
     *
     * @return The cancellation reason or an empty string if authentication was successful.
     */
    public String getCancelReason() {
        return cancelReason;
    }

    /**
     * Returns the http status code for cancelling the authentication process.
     *
     * @return The http status code.
     */
    public int getCode() {
        return code;
    }

}
