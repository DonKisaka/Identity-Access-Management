package identityaccessmanagement.example.Identity.Access.Management.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.Set;

public record RoleRequestDto(
        @NotBlank(message = "Name is required")
        String name,
        String description,
        Set<Long> permissionIds
) {}
