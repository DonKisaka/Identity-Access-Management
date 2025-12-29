package identityaccessmanagement.example.Identity.Access.Management.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginUserDto (
       @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message = "Password is required")
        String password
) {}
