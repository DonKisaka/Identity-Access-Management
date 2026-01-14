package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class InvalidPasswordException extends BaseException {

    private static final String ERROR_CODE = "INVALID_PASSWORD";

    public InvalidPasswordException() {
        super("Invalid password provided", ERROR_CODE, HttpStatus.BAD_REQUEST);
    }

    public InvalidPasswordException(String message) {
        super(message, ERROR_CODE, HttpStatus.BAD_REQUEST);
    }
}
