package identityaccessmanagement.example.Identity.Access.Management.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        String path,
        String message,
        String errorCode,
        int statusCode,
        LocalDateTime timestamp,
        Map<String, String> validationErrors
) {
    public ApiError(String path, String message, String errorCode, int statusCode, LocalDateTime timestamp) {
        this(path, message, errorCode, statusCode, timestamp, null);
    }
}
