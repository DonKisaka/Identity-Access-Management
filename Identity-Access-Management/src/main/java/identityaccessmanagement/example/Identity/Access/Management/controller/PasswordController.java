package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.ChangePasswordRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.ForgotPasswordRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.ResetPasswordRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.service.PasswordService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/password")
public class PasswordController {

    private final PasswordService passwordService;

    public PasswordController(PasswordService passwordService) {
        this.passwordService = passwordService;
    }

    @PostMapping("/forgot")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequestDto dto) {
        passwordService.createPasswordResetToken(dto.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequestDto dto) {
        passwordService.resetPassword(dto.token(), dto.newPassword());
        return ResponseEntity.ok().build();
    }

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
