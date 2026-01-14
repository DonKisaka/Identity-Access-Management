package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class TokenRevokedException extends BaseException {

    private static final String ERROR_CODE = "TOKEN_REVOKED";

    public TokenRevokedException() {
        super("Token has been revoked - possible security breach detected", ERROR_CODE, HttpStatus.UNAUTHORIZED);
    }

    public TokenRevokedException(String message) {
        super(message, ERROR_CODE, HttpStatus.UNAUTHORIZED);
    }
}
