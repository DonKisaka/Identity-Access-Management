package identityaccessmanagement.example.Identity.Access.Management.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record PermissionRequestDto(
        @NotBlank(message = "Name is required")
        @Pattern(regexp = "^[A-Z_]+$", message = "Name must be uppercase with underscores (e.g., USER_READ)")
        String name,

        @NotBlank(message = "Resource is required")
        String resource,

        @NotBlank(message = "Action is required")
        String action,

        String description
) {}
