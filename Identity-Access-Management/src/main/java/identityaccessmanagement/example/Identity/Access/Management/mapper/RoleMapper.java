package identityaccessmanagement.example.Identity.Access.Management.mapper;

import identityaccessmanagement.example.Identity.Access.Management.dto.RoleRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.RoleResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface RoleMapper {
    @Mapping(target = "permissions", expression = "java(mapPermissionsToNames(role.getPermissions()))")
    RoleResponseDto toResponse(Role role);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "permissions", ignore = true)
    Role toEntity(RoleRequestDto roleRequestDto);

    default Set<String> mapPermissionsToNames(Set<Permission> permissions) {
        if (permissions == null) return Set.of();
        return permissions.stream()
                .map(Permission::getName)
                .collect(Collectors.toSet());
    }
}
