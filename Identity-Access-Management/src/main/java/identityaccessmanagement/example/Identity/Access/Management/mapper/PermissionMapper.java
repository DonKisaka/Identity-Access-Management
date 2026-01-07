package identityaccessmanagement.example.Identity.Access.Management.mapper;

import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.model.Permission;

public interface PermissionMapper {
    PermissionResponseDto toResponse(Permission permission);
}
