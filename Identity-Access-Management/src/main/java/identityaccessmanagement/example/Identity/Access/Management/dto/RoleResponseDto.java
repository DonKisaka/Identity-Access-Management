package identityaccessmanagement.example.Identity.Access.Management.dto;

import java.util.Set;

public record RoleResponseDto(
        Long id,
        String name,
        String description,
        Set<String> permissions
) {}
