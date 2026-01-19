package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.RoleRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.RoleResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
@Tag(name = "Roles", description = "APIs for role management including creating roles and assigning permissions")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @Operation(
            summary = "Get all roles",
            description = "Retrieves a list of all roles in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Roles retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping()
    public ResponseEntity<List<RoleResponseDto>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @Operation(
            summary = "Get role by ID",
            description = "Retrieves a specific role by its ID"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role found",
                    content = @Content(schema = @Schema(implementation = RoleResponseDto.class))),
            @ApiResponse(responseCode = "404", description = "Role not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/{id}")
    public ResponseEntity<RoleResponseDto> getRoleById(
            @Parameter(description = "ID of the role to retrieve") @PathVariable Long id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    @Operation(
            summary = "Get role by name",
            description = "Retrieves a specific role by its name"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role found",
                    content = @Content(schema = @Schema(implementation = RoleResponseDto.class))),
            @ApiResponse(responseCode = "404", description = "Role not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/name/{name}")
    public ResponseEntity<RoleResponseDto> getRoleByName(
            @Parameter(description = "Name of the role to retrieve") @PathVariable String name) {
        return ResponseEntity.ok(roleService.getRoleByName(name));
    }

    @Operation(
            summary = "Create a new role",
            description = "Creates a new role in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Role created successfully",
                    content = @Content(schema = @Schema(implementation = RoleResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input data",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "Role with this name already exists",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping()
    public ResponseEntity<RoleResponseDto> createRole(@Valid  @RequestBody RoleRequestDto dto) {
        RoleResponseDto role = roleService.createRole(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }

    @Operation(
            summary = "Add permission to role",
            description = "Assigns a permission to an existing role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permission added to role successfully"),
            @ApiResponse(responseCode = "404", description = "Role or permission not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping("/{roleName}/permissions/{permissionId}")
    public ResponseEntity<Void> addPermissionToRole(
            @Parameter(description = "Name of the role") @PathVariable String roleName,
            @Parameter(description = "ID of the permission to add") @PathVariable Long permissionId) {
        roleService.addPermissionToRole(roleName, permissionId);
        return ResponseEntity.ok().build();
    }
}
