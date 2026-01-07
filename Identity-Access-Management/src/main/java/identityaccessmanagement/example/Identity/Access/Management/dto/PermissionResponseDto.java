package identityaccessmanagement.example.Identity.Access.Management.dto;

public record PermissionResponseDto(
        Long id,
        String name,
        String action,
        String resource,
        String description
) {}
