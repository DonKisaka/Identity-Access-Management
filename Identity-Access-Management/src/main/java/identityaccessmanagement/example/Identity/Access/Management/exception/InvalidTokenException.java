package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class InvalidTokenException extends BaseException {

    private static final String ERROR_CODE = "INVALID_TOKEN";

    public InvalidTokenException() {
        super("Token is invalid or has expired", ERROR_CODE, HttpStatus.UNAUTHORIZED);
    }

    public InvalidTokenException(String message) {
        super(message, ERROR_CODE, HttpStatus.UNAUTHORIZED);
    }
}
