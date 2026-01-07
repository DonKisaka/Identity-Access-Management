package identityaccessmanagement.example.Identity.Access.Management.dto;

import jakarta.validation.constraints.NotBlank;

public record PermissionRequestDto(
        @NotBlank(message = "Name is required")
        String name,

        @NotBlank(message = "Resource is required")
        String resource,

        @NotBlank(message = "Action is required")
        String action,

        String description
) {}
