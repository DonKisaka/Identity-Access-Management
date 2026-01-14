package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class BadCredentialsException extends BaseException {

    private static final String ERROR_CODE = "BAD_CREDENTIALS";

    public BadCredentialsException() {
        super("Invalid username or password", ERROR_CODE, HttpStatus.UNAUTHORIZED);
    }

    public BadCredentialsException(String message) {
        super(message, ERROR_CODE, HttpStatus.UNAUTHORIZED);
    }
}
