package identityaccessmanagement.example.Identity.Access.Management.dto;

public record AuthenticationResponseDto(
        String username,
        String email,
        String token,
        String refreshToken,
        Long expiresIn
) {}
