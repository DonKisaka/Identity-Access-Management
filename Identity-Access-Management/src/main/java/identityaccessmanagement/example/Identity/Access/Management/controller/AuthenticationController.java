package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.AuthenticationResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.CreateUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.LoginUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.TokenRefreshRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
            @Valid @RequestBody CreateUserDto dto,
            HttpServletRequest request
    ) {
        String ipAddress = extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        AuthenticationResponseDto response = authenticationService.signUp(dto, ipAddress, userAgent);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponseDto> authenticate(
            @Valid @RequestBody LoginUserDto dto,
            HttpServletRequest request
    ) {
        String ipAddress = extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        AuthenticationResponseDto response = authenticationService.authenticate(dto, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponseDto> refreshToken(
            @Valid @RequestBody TokenRefreshRequestDto dto,
            HttpServletRequest request
            ) {
        String ipAddress = extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        AuthenticationResponseDto response = authenticationService.refreshToken(dto.refreshToken(), ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody TokenRefreshRequestDto dto) {
        authenticationService.logout(dto.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAllDevices(Authentication authentication) {
        authenticationService.logoutAllDevices(authentication.getName());
        return ResponseEntity.noContent().build();
    }

    private String extractIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
