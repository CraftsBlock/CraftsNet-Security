package de.craftsblock.cnet.modules.security.auth;

import de.craftsblock.craftsnet.api.http.Exchange;
import de.craftsblock.craftsnet.api.http.Request;

/**
 * The {@link AuthAdapter} interface defines the contract for implementing custom authentication mechanisms.
 * Classes implementing this interface provide the logic for authenticating requests and handling
 * authentication success or failure.
 *
 * <p>It includes a method for performing authentication on a given {@link Request} and a default method
 * for handling authentication failure by setting the appropriate state in an {@link AuthResult} object.</p>
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @since 1.0.0-SNAPSHOT
 */
public interface AuthAdapter {

    /**
     * Authenticates the incoming request. Implementations of this method should define the logic for
     * checking whether the request is authorized or not.
     *
     * @param result   The {@link AuthResult} object where the outcome of the authentication process is stored.
     * @param exchange The {@link Exchange} object representing the HTTP request.
     */
    void authenticate(AuthResult result, Exchange exchange);

    /**
     * Marks the authentication process as failed. This method is used to set the failure state
     * in the {@link AuthResult} object, including the reason for the failure.
     *
     * @param result The {@link AuthResult} object that stores the result of the authentication process.
     * @param reason A string explaining why the authentication failed.
     */
    default void failAuth(AuthResult result, String reason) {
        result.cancel(reason);
    }

    /**
     * Marks the authentication process as failed. This method is used to set the failure state
     * in the {@link AuthResult} object, including the reason for the failure.
     *
     * @param code   The response http code.
     * @param result The {@link AuthResult} object that stores the result of the authentication process.
     * @param reason A string explaining why the authentication failed.
     */
    default void failAuth(AuthResult result, int code, String reason) {
        result.cancel(code, reason);
    }

}
