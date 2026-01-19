package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.AuthenticationResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.CreateUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.LoginUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.TokenRefreshRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Authentication", description = "APIs for user authentication including signup, login, token refresh, and logout")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Operation(
            summary = "Register a new user",
            description = "Creates a new user account and returns JWT access and refresh tokens"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User successfully registered",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input data",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "User with this email/username already exists",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
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

    @Operation(
            summary = "Authenticate user",
            description = "Authenticates a user with username/email and password, returns JWT access and refresh tokens"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully authenticated",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Account is locked or disabled",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
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

    @Operation(
            summary = "Refresh access token",
            description = "Uses a valid refresh token to obtain a new access token"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token successfully refreshed",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
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

    @Operation(
            summary = "Logout user",
            description = "Revokes the specified refresh token, ending the session on the current device"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Successfully logged out"),
            @ApiResponse(responseCode = "401", description = "Invalid refresh token",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody TokenRefreshRequestDto dto) {
        authenticationService.logout(dto.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Logout from all devices",
            description = "Revokes all refresh tokens for the authenticated user, ending sessions on all devices"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Successfully logged out from all devices"),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @SecurityRequirement(name = "bearerAuth")
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
