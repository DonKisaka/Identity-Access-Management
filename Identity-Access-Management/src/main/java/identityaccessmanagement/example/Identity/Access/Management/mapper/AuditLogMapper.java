package identityaccessmanagement.example.Identity.Access.Management.mapper;

import identityaccessmanagement.example.Identity.Access.Management.dto.AuditLogResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.model.AuditLog;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "spring")
public interface AuditLogMapper {

    @Mapping(source = "user.username", target = "username")
    AuditLogResponseDto toResponse(AuditLog auditLog);


    List<AuditLogResponseDto> toResponseList(List<AuditLog> auditLogs);
}
