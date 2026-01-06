package identityaccessmanagement.example.Identity.Access.Management.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequestDto (
        @NotBlank
        String oldPassword,

        @NotBlank
        @Size(min = 8)
        String newPassword
) {}
