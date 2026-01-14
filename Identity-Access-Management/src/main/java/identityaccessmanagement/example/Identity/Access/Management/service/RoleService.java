package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.dto.RoleRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.RoleResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.DuplicateResourceException;
import identityaccessmanagement.example.Identity.Access.Management.exception.ResourceNotFoundException;
import identityaccessmanagement.example.Identity.Access.Management.mapper.RoleMapper;
import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.repository.PermissionRepository;
import identityaccessmanagement.example.Identity.Access.Management.repository.RoleRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RoleMapper roleMapper;

    public RoleService(RoleRepository roleRepository, PermissionRepository permissionRepository, RoleMapper roleMapper) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.roleMapper = roleMapper;
    }

    public List<RoleResponseDto> getAllRoles() {
        return roleRepository.findAll().stream().map(roleMapper::toResponse).toList();
    }

    public RoleResponseDto getRoleById(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", id));
        return roleMapper.toResponse(role);
    }

    public RoleResponseDto getRoleByName(String name) {
        Role role = roleRepository.findByName(name)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "name", name));
        return roleMapper.toResponse(role);
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public RoleResponseDto createRole(RoleRequestDto dto) {
        if (roleRepository.findByName(dto.name()).isPresent()) {
            throw new DuplicateResourceException("Role", "name", dto.name());
        }

        Set<Permission> permissions = new HashSet<>();
        if (dto.permissionIds() != null) {
            permissions = dto.permissionIds().stream()
                    .map(id -> permissionRepository.findById(id)
                            .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", id)))
                    .collect(Collectors.toSet());
        }

        Role role = Role.builder()
                .name(dto.name())
                .description(dto.description())
                .permissions(permissions)
                .build();

        return roleMapper.toResponse(roleRepository.save(role));
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void addPermissionToRole(String roleName, Long permissionId) {
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "name", roleName));

        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", permissionId));

        role.getPermissions().add(permission);
        roleRepository.save(role);
    }
}
