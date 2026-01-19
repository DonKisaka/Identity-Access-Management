package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.AuditLogResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ApiError;
import identityaccessmanagement.example.Identity.Access.Management.service.AuditLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/audit-logs")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Audit Logs", description = "APIs for viewing audit logs. Requires ADMIN role.")
public class AuditLogController {

    private final AuditLogService auditLogService;

    public AuditLogController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Operation(
            summary = "Get audit logs by user",
            description = "Retrieves a paginated list of audit logs for a specific user. Requires ADMIN role."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Audit logs retrieved successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "User does not have ADMIN role",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/user/{userId}")
    public ResponseEntity<Page<AuditLogResponseDto>> getLogsByUser(
            @Parameter(description = "ID of the user whose logs to retrieve") @PathVariable Long userId,
            @Parameter(description = "Pagination parameters") Pageable pageable
    ) {
        return ResponseEntity.ok(auditLogService.getLogsByUser(userId, pageable));
    }

    @Operation(
            summary = "Get audit logs by date range",
            description = "Retrieves a paginated list of audit logs within the specified date range. Requires ADMIN role."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Audit logs retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid date range format",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "User does not have ADMIN role",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    @GetMapping("/date-range")
    public ResponseEntity<Page<AuditLogResponseDto>> getLogsByDateRange(
            @Parameter(description = "Start date and time (ISO format)", example = "2024-01-01T00:00:00")
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @Parameter(description = "End date and time (ISO format)", example = "2024-12-31T23:59:59")
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end,
            @Parameter(description = "Pagination parameters") Pageable pageable
    ) {
        return ResponseEntity.ok(auditLogService.getLogsByDateRange(start, end, pageable));
    }
}
