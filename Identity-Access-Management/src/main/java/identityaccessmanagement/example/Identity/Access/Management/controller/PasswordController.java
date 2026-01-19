package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.ChangePasswordRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.ForgotPasswordRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.ResetPasswordRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.PasswordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/password")
@Tag(name = "Password Management", description = "APIs for password operations including forgot password, reset password, and change password")
public class PasswordController {

    private final PasswordService passwordService;

    public PasswordController(PasswordService passwordService) {
        this.passwordService = passwordService;
    }

    @Operation(
            summary = "Request password reset",
            description = "Initiates the password reset process by sending a reset token to the user's email address"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset email sent if the email exists"),
            @ApiResponse(responseCode = "400", description = "Invalid email format",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/forgot")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequestDto dto) {
        passwordService.createPasswordResetToken(dto.email());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "Reset password with token",
            description = "Resets the user's password using a valid password reset token"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "400", description = "Password does not meet requirements",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/reset")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequestDto dto) {
        passwordService.resetPassword(dto.token(), dto.newPassword());
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "Change password",
            description = "Allows an authenticated user to change their password by providing the current password and a new password"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid current password",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "400", description = "New password does not meet requirements",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/change")
    public ResponseEntity<Void> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequestDto dto) {
        passwordService.changePassword(
                authentication.getName(),
                dto.oldPassword(),
                dto.newPassword()
        );
        return ResponseEntity.ok().build();
    }
}
