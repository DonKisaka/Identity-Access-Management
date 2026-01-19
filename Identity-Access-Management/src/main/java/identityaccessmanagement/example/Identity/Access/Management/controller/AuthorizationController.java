package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.AuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/v1/authorization")
@Tag(name = "Authorization", description = "APIs for managing user role assignments")
public class AuthorizationController {

    private final AuthorizationService  authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Operation(
            summary = "Assign role to user",
            description = "Assigns a specific role to a user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role assigned successfully"),
            @ApiResponse(responseCode = "404", description = "User or role not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/users/{userId}/roles/{roleName}")
    public ResponseEntity<Void> assignRoleToUser(
            @Parameter(description = "ID of the user to assign the role to") @PathVariable Long userId,
            @Parameter(description = "Name of the role to assign") @PathVariable String roleName) {
        authorizationService.assignRoleToUser(userId, roleName);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "Remove role from user",
            description = "Removes a specific role from a user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Role removed successfully"),
            @ApiResponse(responseCode = "404", description = "User or role not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @DeleteMapping("/users/{userId}/roles/{roleName}")
    public ResponseEntity<Void> removeRoleFromUser(
            @Parameter(description = "ID of the user to remove the role from") @PathVariable Long userId,
            @Parameter(description = "Name of the role to remove") @PathVariable String roleName) {
        authorizationService.removeRoleFromUser(userId, roleName);
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Get user roles",
            description = "Retrieves all roles assigned to a specific user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Roles retrieved successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/users/{userId}/roles")
    public ResponseEntity<Set<String>> getUserRoles(
            @Parameter(description = "ID of the user whose roles to retrieve") @PathVariable Long userId) {
        return ResponseEntity.ok(authorizationService.getUserRoles(userId));
    }
}
