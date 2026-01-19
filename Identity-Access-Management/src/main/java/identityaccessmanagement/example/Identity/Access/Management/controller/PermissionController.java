package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
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
@RequestMapping("/api/v1/permissions")
@Tag(name = "Permissions", description = "APIs for permission management including creating and listing permissions")
public class PermissionController {

    private final PermissionService permissionService;

    public PermissionController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @Operation(
            summary = "Get all permissions",
            description = "Retrieves a list of all permissions in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping()
    public ResponseEntity<List<PermissionResponseDto>> getAllPermissions() {
        return ResponseEntity.ok(permissionService.getAllPermissions());
    }

    @Operation(
            summary = "Create a new permission",
            description = "Creates a new permission in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Permission created successfully",
                    content = @Content(schema = @Schema(implementation = PermissionResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input data",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "409", description = "Permission with this name already exists",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @PostMapping()
    public ResponseEntity<PermissionResponseDto> createPermission(@Valid  @RequestBody PermissionRequestDto dto) {
        PermissionResponseDto permissionResponseDto = permissionService.createPermission(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(permissionResponseDto);
    }
}
