package identityaccessmanagement.example.Identity.Access.Management.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenRefreshRequestDto(
        @NotBlank String refreshToken
) {}
