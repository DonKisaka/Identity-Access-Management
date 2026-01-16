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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("RoleService Tests")
class RoleServiceTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private RoleMapper roleMapper;

    @InjectMocks
    private RoleService roleService;

    @Captor
    private ArgumentCaptor<Role> roleCaptor;

    private Role adminRole;
    private Role userRole;
    private Permission readPermission;
    private Permission writePermission;
    private RoleResponseDto adminRoleResponse;
    private RoleResponseDto userRoleResponse;

    @BeforeEach
    void setUp() {
        readPermission = Permission.builder()
                .id(1L)
                .name("READ_USERS")
                .resource("users")
                .action("read")
                .description("Read users")
                .build();

        writePermission = Permission.builder()
                .id(2L)
                .name("WRITE_USERS")
                .resource("users")
                .action("write")
                .description("Write users")
                .build();

        adminRole = Role.builder()
                .id(1L)
                .name("ADMIN")
                .description("Administrator role")
                .permissions(new HashSet<>(Set.of(readPermission, writePermission)))
                .build();

        userRole = Role.builder()
                .id(2L)
                .name("USER")
                .description("Standard user role")
                .permissions(new HashSet<>(Set.of(readPermission)))
                .build();

        adminRoleResponse = new RoleResponseDto(1L, "ADMIN", "Administrator role", Set.of("READ_USERS", "WRITE_USERS"));
        userRoleResponse = new RoleResponseDto(2L, "USER", "Standard user role", Set.of("READ_USERS"));
    }

    @Nested
    @DisplayName("getAllRoles Tests")
    class GetAllRolesTests {

        @Test
        @DisplayName("GIVEN roles exist WHEN getAllRoles is called THEN returns all roles")
        void shouldReturnAllRoles() {
            // GIVEN
            given(roleRepository.findAll()).willReturn(List.of(adminRole, userRole));
            given(roleMapper.toResponse(adminRole)).willReturn(adminRoleResponse);
            given(roleMapper.toResponse(userRole)).willReturn(userRoleResponse);

            // WHEN
            List<RoleResponseDto> result = roleService.getAllRoles();

            // THEN
            assertThat(result).hasSize(2);
            assertThat(result).extracting(RoleResponseDto::name)
                    .containsExactlyInAnyOrder("ADMIN", "USER");

            // Verification
            verify(roleRepository, times(1)).findAll();
            verify(roleMapper, times(2)).toResponse(any(Role.class));
        }

        @Test
        @DisplayName("GIVEN no roles exist WHEN getAllRoles is called THEN returns empty list")
        void shouldReturnEmptyListWhenNoRoles() {
            // GIVEN
            given(roleRepository.findAll()).willReturn(List.of());

            // WHEN
            List<RoleResponseDto> result = roleService.getAllRoles();

            // THEN
            assertThat(result).isEmpty();
            verify(roleMapper, never()).toResponse(any());
        }
    }

    @Nested
    @DisplayName("getRoleById Tests")
    class GetRoleByIdTests {

        @Test
        @DisplayName("GIVEN a valid role ID WHEN getRoleById is called THEN returns the role")
        void shouldReturnRoleWhenIdExists() {
            // GIVEN
            Long roleId = 1L;
            given(roleRepository.findById(roleId)).willReturn(Optional.of(adminRole));
            given(roleMapper.toResponse(adminRole)).willReturn(adminRoleResponse);

            // WHEN
            RoleResponseDto result = roleService.getRoleById(roleId);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.id()).isEqualTo(roleId);
            assertThat(result.name()).isEqualTo("ADMIN");
            verify(roleRepository).findById(roleId);
        }

        @Test
        @DisplayName("GIVEN a non-existent role ID WHEN getRoleById is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenRoleIdNotFound() {
            // GIVEN
            Long nonExistentId = 999L;
            given(roleRepository.findById(nonExistentId)).willReturn(Optional.empty());

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> roleService.getRoleById(nonExistentId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Role")
                    .hasMessageContaining("id");

            verify(roleMapper, never()).toResponse(any());
        }
    }

    @Nested
    @DisplayName("getRoleByName Tests")
    class GetRoleByNameTests {

        @Test
        @DisplayName("GIVEN a valid role name WHEN getRoleByName is called THEN returns the role")
        void shouldReturnRoleWhenNameExists() {
            // GIVEN
            String roleName = "ADMIN";
            given(roleRepository.findByName(roleName)).willReturn(Optional.of(adminRole));
            given(roleMapper.toResponse(adminRole)).willReturn(adminRoleResponse);

            // WHEN
            RoleResponseDto result = roleService.getRoleByName(roleName);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.name()).isEqualTo(roleName);
            verify(roleRepository).findByName(roleName);
        }

        @Test
        @DisplayName("GIVEN a non-existent role name WHEN getRoleByName is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenRoleNameNotFound() {
            // GIVEN
            String nonExistentName = "SUPERADMIN";
            given(roleRepository.findByName(nonExistentName)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> roleService.getRoleByName(nonExistentName))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Role")
                    .hasMessageContaining("name");
        }
    }

    @Nested
    @DisplayName("createRole Tests")
    class CreateRoleTests {

        @Test
        @DisplayName("GIVEN a valid role request WHEN createRole is called THEN creates and returns the role")
        void shouldCreateRoleSuccessfully() {
            // GIVEN
            RoleRequestDto requestDto = new RoleRequestDto("MODERATOR", "Moderator role", Set.of(1L));
            RoleResponseDto expectedResponse = new RoleResponseDto(3L, "MODERATOR", "Moderator role", Set.of("READ_USERS"));

            given(roleRepository.findByName("MODERATOR")).willReturn(Optional.empty());
            given(permissionRepository.findById(1L)).willReturn(Optional.of(readPermission));
            given(roleRepository.save(any(Role.class))).willAnswer(invocation -> {
                Role savedRole = invocation.getArgument(0);
                savedRole.setId(3L);
                return savedRole;
            });
            given(roleMapper.toResponse(any(Role.class))).willReturn(expectedResponse);

            // WHEN
            RoleResponseDto result = roleService.createRole(requestDto);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.name()).isEqualTo("MODERATOR");

            // ArgumentCaptor to verify saved role
            verify(roleRepository).save(roleCaptor.capture());
            Role capturedRole = roleCaptor.getValue();
            assertThat(capturedRole.getName()).isEqualTo("MODERATOR");
            assertThat(capturedRole.getDescription()).isEqualTo("Moderator role");
            assertThat(capturedRole.getPermissions()).hasSize(1);
        }

        @Test
        @DisplayName("GIVEN a role request with no permissions WHEN createRole is called THEN creates role without permissions")
        void shouldCreateRoleWithoutPermissions() {
            // GIVEN
            RoleRequestDto requestDto = new RoleRequestDto("GUEST", "Guest role", null);
            RoleResponseDto expectedResponse = new RoleResponseDto(4L, "GUEST", "Guest role", Set.of());

            given(roleRepository.findByName("GUEST")).willReturn(Optional.empty());
            given(roleRepository.save(any(Role.class))).willAnswer(invocation -> {
                Role savedRole = invocation.getArgument(0);
                savedRole.setId(4L);
                return savedRole;
            });
            given(roleMapper.toResponse(any(Role.class))).willReturn(expectedResponse);

            // WHEN
            roleService.createRole(requestDto);

            // THEN
            verify(roleRepository).save(roleCaptor.capture());
            Role capturedRole = roleCaptor.getValue();
            assertThat(capturedRole.getPermissions()).isEmpty();

            // Verification: permission repository should not be called
            verify(permissionRepository, never()).findById(anyLong());
        }

        @Test
        @DisplayName("GIVEN a duplicate role name WHEN createRole is called THEN throws DuplicateResourceException")
        void shouldThrowExceptionWhenRoleAlreadyExists() {
            // GIVEN
            RoleRequestDto requestDto = new RoleRequestDto("ADMIN", "Duplicate admin", null);
            given(roleRepository.findByName("ADMIN")).willReturn(Optional.of(adminRole));

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> roleService.createRole(requestDto))
                    .isInstanceOf(DuplicateResourceException.class)
                    .hasMessageContaining("Role")
                    .hasMessageContaining("name")
                    .hasMessageContaining("ADMIN");

            // Verification: save should never be called
            verify(roleRepository, never()).save(any());
        }

        @Test
        @DisplayName("GIVEN a role request with non-existent permission WHEN createRole is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenPermissionNotFound() {
            // GIVEN
            RoleRequestDto requestDto = new RoleRequestDto("MODERATOR", "Moderator role", Set.of(999L));

            given(roleRepository.findByName("MODERATOR")).willReturn(Optional.empty());
            given(permissionRepository.findById(999L)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> roleService.createRole(requestDto))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Permission");

            verify(roleRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("addPermissionToRole Tests")
    class AddPermissionToRoleTests {

        @Test
        @DisplayName("GIVEN valid role and permission WHEN addPermissionToRole is called THEN adds permission to role")
        void shouldAddPermissionToRole() {
            // GIVEN
            String roleName = "USER";
            Long permissionId = 2L;

            // Create a copy of userRole with mutable permissions
            Role mutableUserRole = Role.builder()
                    .id(2L)
                    .name("USER")
                    .description("Standard user role")
                    .permissions(new HashSet<>(Set.of(readPermission)))
                    .build();

            given(roleRepository.findByName(roleName)).willReturn(Optional.of(mutableUserRole));
            given(permissionRepository.findById(permissionId)).willReturn(Optional.of(writePermission));
            given(roleRepository.save(any(Role.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            roleService.addPermissionToRole(roleName, permissionId);

            // THEN - ArgumentCaptor
            verify(roleRepository).save(roleCaptor.capture());
            Role savedRole = roleCaptor.getValue();

            assertThat(savedRole.getPermissions()).hasSize(2);
            assertThat(savedRole.getPermissions()).extracting(Permission::getName)
                    .containsExactlyInAnyOrder("READ_USERS", "WRITE_USERS");
        }

        @Test
        @DisplayName("GIVEN non-existent role WHEN addPermissionToRole is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenRoleNotFoundForAddPermission() {
            // GIVEN
            given(roleRepository.findByName("NONEXISTENT")).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> roleService.addPermissionToRole("NONEXISTENT", 1L))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Role");

            verify(permissionRepository, never()).findById(anyLong());
            verify(roleRepository, never()).save(any());
        }

        @Test
        @DisplayName("GIVEN non-existent permission WHEN addPermissionToRole is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenPermissionNotFoundForAddPermission() {
            // GIVEN
            given(roleRepository.findByName("USER")).willReturn(Optional.of(userRole));
            given(permissionRepository.findById(999L)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> roleService.addPermissionToRole("USER", 999L))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Permission");

            verify(roleRepository, never()).save(any());
        }
    }
}
