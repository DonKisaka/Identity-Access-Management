package identityaccessmanagement.example.Identity.Access.Management.dto;

public record AuthenticationResponseDto(
        String accessToken,
        String refreshToken,
        Long expiresIn
) {}
