package identityaccessmanagement.example.Identity.Access.Management.dto;

import java.time.LocalDateTime;

public record AuditLogResponseDto(
   Long id,
   String action,
   String status,
   String severity,
   String ipAddress,
   LocalDateTime createdAt,
   String username
) {}
