package identityaccessmanagement.example.Identity.Access.Management.exception;

import org.springframework.http.HttpStatus;


public class ResourceNotFoundException extends BaseException {

    private static final String ERROR_CODE = "RESOURCE_NOT_FOUND";

    public ResourceNotFoundException(String message) {
        super(message, ERROR_CODE, HttpStatus.NOT_FOUND);
    }

    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(
                String.format("%s not found with %s: '%s'", resourceName, fieldName, fieldValue),
                ERROR_CODE,
                HttpStatus.NOT_FOUND
        );
    }
}
