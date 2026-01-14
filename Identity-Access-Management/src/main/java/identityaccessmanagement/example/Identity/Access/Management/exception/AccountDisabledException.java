package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class AccountDisabledException extends BaseException {

    private static final String ERROR_CODE = "ACCOUNT_DISABLED";

    public AccountDisabledException() {
        super("Account has been disabled", ERROR_CODE, HttpStatus.FORBIDDEN);
    }

    public AccountDisabledException(String message) {
        super(message, ERROR_CODE, HttpStatus.FORBIDDEN);
    }
}
