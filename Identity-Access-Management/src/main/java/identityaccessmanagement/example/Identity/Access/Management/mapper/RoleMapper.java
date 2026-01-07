package identityaccessmanagement.example.Identity.Access.Management.mapper;

import identityaccessmanagement.example.Identity.Access.Management.dto.RoleRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.RoleResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface RoleMapper {
    RoleResponseDto toResponse(Role role);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "permissions", ignore = true)
    Role toEntity(RoleRequestDto roleRequestDto);
}
