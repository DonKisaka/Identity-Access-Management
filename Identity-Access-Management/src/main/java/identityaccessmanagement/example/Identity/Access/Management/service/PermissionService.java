package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.mapper.PermissionMapper;
import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.repository.PermissionRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final PermissionMapper permissionMapper;

    public PermissionService(PermissionRepository permissionRepository, PermissionMapper permissionMapper) {
        this.permissionRepository = permissionRepository;
        this.permissionMapper = permissionMapper;
    }

    public List<PermissionResponseDto> getAllPermissions() {
        return permissionRepository.findAll().stream().map(permissionMapper::toResponse).toList();
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public PermissionResponseDto createPermission(PermissionRequestDto dto) {
        if (permissionRepository.findByName(dto.name()).isPresent()) {
            throw new IllegalArgumentException("Permission already exists!");
        }

        Permission permission = Permission.builder()
                .name(dto.name())
                .resource(dto.resource())
                .action(dto.action())
                .description(dto.description())
                .build();

        return permissionMapper.toResponse(permissionRepository.save(permission));
    }
}
