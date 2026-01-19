package identityaccessmanagement.example.Identity.Access.Management.mapper;

import identityaccessmanagement.example.Identity.Access.Management.dto.CreateUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.UserResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "roles", expression = "java(mapRolesToNames(user.getRoles()))")
    @Mapping(target = "permissions", expression = "java(mapPermissionsToNames(user.getRoles()))")
    UserResponseDto toResponse(User user);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "password", ignore = true)
    @Mapping(target = "roles", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "isLocked", ignore = true)
    @Mapping(target = "failedLoginAttempts", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "lastLogin", ignore = true)
    User toEntity(CreateUserDto dto);

    default Set<String> mapRolesToNames(Set<Role> roles) {
        if (roles == null) return Set.of();
        return roles.stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
    }

    default Set<String> mapPermissionsToNames(Set<Role> roles) {
        if (roles == null) return Set.of();
        return roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toSet());
    }
}
