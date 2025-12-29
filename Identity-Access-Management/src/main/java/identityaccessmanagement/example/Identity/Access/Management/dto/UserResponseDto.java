package identityaccessmanagement.example.Identity.Access.Management.dto;

import java.util.Set;

public record UserResponseDto(
        Long id,
        String username,
        String email,
        Boolean enabled,
        Set<String> roles,
        Set<String> permissions
) {}
