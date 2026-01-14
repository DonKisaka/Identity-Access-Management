package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class AccountLockedException extends BaseException {

    private static final String ERROR_CODE = "ACCOUNT_LOCKED";

    public AccountLockedException() {
        super("Account is locked due to too many failed login attempts", ERROR_CODE, HttpStatus.FORBIDDEN);
    }

    public AccountLockedException(String message) {
        super(message, ERROR_CODE, HttpStatus.FORBIDDEN);
    }
}
