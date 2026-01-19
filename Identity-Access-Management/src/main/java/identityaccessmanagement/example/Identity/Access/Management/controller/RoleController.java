package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.RoleRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.RoleResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.service.RoleService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping()
    @PreAuthorize("hasAuthority('roles:read')")
    public ResponseEntity<List<RoleResponseDto>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('roles:read')")
    public ResponseEntity<RoleResponseDto> getRoleById(@PathVariable Long id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    @GetMapping("/name/{name}")
    @PreAuthorize("hasAuthority('roles:read')")
    public ResponseEntity<RoleResponseDto> getRoleByName(@PathVariable String name) {
        return ResponseEntity.ok(roleService.getRoleByName(name));
    }

    @PostMapping()
    @PreAuthorize("hasAuthority('roles:create')")
    public ResponseEntity<RoleResponseDto> createRole(@Valid @RequestBody RoleRequestDto dto) {
        RoleResponseDto role = roleService.createRole(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }

    @PostMapping("/{roleName}/permissions/{permissionId}")
    @PreAuthorize("hasAuthority('roles:update')")
    public ResponseEntity<Void> addPermissionToRole(@PathVariable String roleName, @PathVariable Long permissionId) {
        roleService.addPermissionToRole(roleName, permissionId);
        return ResponseEntity.ok().build();
    }
}
