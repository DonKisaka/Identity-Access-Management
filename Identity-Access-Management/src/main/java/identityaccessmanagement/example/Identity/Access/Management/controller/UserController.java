package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.UserResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Users", description = "APIs for user management including retrieving user information and account status management")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Operation(
            summary = "Get current user",
            description = "Retrieves the profile information of the currently authenticated user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User profile retrieved successfully",
                    content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getCurrentUser(
            Authentication authentication
    ) {
        UserResponseDto user = userService.getUserByUsername(authentication.getName());
        return ResponseEntity.ok(user);
    }

    @Operation(
            summary = "Get user by username",
            description = "Retrieves user profile information by username"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User found",
                    content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/{username}")
    public ResponseEntity<UserResponseDto> getUserByUsername(
            @Parameter(description = "Username of the user to retrieve") @PathVariable String username) {
        UserResponseDto user = userService.getUserByUsername(username);
        return ResponseEntity.ok(user);
    }

    @Operation(
            summary = "Get all users",
            description = "Retrieves a paginated list of all users in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping()
    public ResponseEntity<Page<UserResponseDto>> getAllUsers(
            @Parameter(description = "Pagination parameters") Pageable pageable) {
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }

    @Operation(
            summary = "Unlock user account",
            description = "Unlocks a user account that was locked due to failed login attempts"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User account unlocked successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/{userId}/unlock")
    public ResponseEntity<Void> unlockUser(
            @Parameter(description = "ID of the user to unlock") @PathVariable Long userId) {
        userService.unlockUser(userId);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "Disable user account",
            description = "Disables a user account, preventing the user from logging in"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User account disabled successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/{userId}/disable")
    public ResponseEntity<Void> disableUser(
            @Parameter(description = "ID of the user to disable") @PathVariable Long userId) {
        userService.disableUser(userId);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "Enable user account",
            description = "Re-enables a previously disabled user account"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User account enabled successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/{userId}/enable")
    public ResponseEntity<Void> enableUser(
            @Parameter(description = "ID of the user to enable") @PathVariable Long userId) {
        userService.enableUser(userId);
        return ResponseEntity.ok().build();
    }
}
