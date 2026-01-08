package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.AuthenticationResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.CreateUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.LoginUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.TokenRefreshRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthenticationResponseDto> signUp(
            @Valid @RequestBody CreateUserDto dto
    ) {
        AuthenticationResponseDto response = authenticationService.signUp(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponseDto> authenticate(
            @Valid @RequestBody LoginUserDto dto
    ) {
        AuthenticationResponseDto response = authenticationService.authenticate(dto);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponseDto> refreshToken(
            @Valid @RequestBody TokenRefreshRequestDto dto
            ) {
        AuthenticationResponseDto response = authenticationService.refreshToken(dto.refreshToken());
        return ResponseEntity.ok(response);
    }
}
