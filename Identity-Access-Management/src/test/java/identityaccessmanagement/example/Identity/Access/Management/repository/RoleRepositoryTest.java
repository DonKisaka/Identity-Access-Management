package identityaccessmanagement.example.Identity.Access.Management.repository;

import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest
@DisplayName("RoleRepository Tests")
class RoleRepositoryTest {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    private Role adminRole;
    private Role userRole;
    private Permission readPermission;
    private Permission writePermission;

    @BeforeEach
    void setUp() {
        // Clear previous test data
        roleRepository.deleteAll();
        permissionRepository.deleteAll();

        // Create and persist permissions
        readPermission = Permission.builder()
                .name("READ_DATA")
                .resource("data")
                .action("read")
                .description("Read data permission")
                .build();
        readPermission = permissionRepository.save(readPermission);

        writePermission = Permission.builder()
                .name("WRITE_DATA")
                .resource("data")
                .action("write")
                .description("Write data permission")
                .build();
        writePermission = permissionRepository.save(writePermission);

        // Create and persist roles - use mutable HashSet so permissions can be modified in tests
        adminRole = Role.builder()
                .name("ADMIN")
                .description("Administrator role with full access")
                .permissions(new HashSet<>(Set.of(readPermission, writePermission)))
                .build();
        adminRole = roleRepository.save(adminRole);

        userRole = Role.builder()
                .name("USER")
                .description("Standard user role")
                .permissions(new HashSet<>(Set.of(readPermission)))
                .build();
        userRole = roleRepository.save(userRole);
    }

    @Nested
    @DisplayName("findByName Tests")
    class FindByNameTests {

        @Test
        @DisplayName("GIVEN role exists WHEN findByName is called THEN returns the role")
        void shouldFindRoleByName() {
            // GIVEN - roles already persisted in setUp

            // WHEN
            Optional<Role> result = roleRepository.findByName("ADMIN");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("ADMIN");
            assertThat(result.get().getDescription()).isEqualTo("Administrator role with full access");
        }

        @Test
        @DisplayName("GIVEN role doesn't exist WHEN findByName is called THEN returns empty")
        void shouldReturnEmptyWhenRoleNotFound() {
            // GIVEN - no role with this name

            // WHEN
            Optional<Role> result = roleRepository.findByName("SUPERADMIN");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN role name is case-sensitive WHEN findByName with different case THEN returns empty")
        void shouldBeCaseSensitiveForRoleName() {
            // GIVEN - role with uppercase name

            // WHEN
            Optional<Role> result = roleRepository.findByName("admin");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN role with permissions WHEN findByName is called THEN returns role with permissions")
        void shouldReturnRoleWithPermissions() {
            // GIVEN - role with permissions already persisted

            // WHEN
            Optional<Role> result = roleRepository.findByName("ADMIN");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getPermissions()).hasSize(2);
            assertThat(result.get().getPermissions())
                    .extracting(Permission::getName)
                    .containsExactlyInAnyOrder("READ_DATA", "WRITE_DATA");
        }
    }

    @Nested
    @DisplayName("CRUD Operations Tests")
    class CrudOperationsTests {

        @Test
        @DisplayName("GIVEN new role WHEN save is called THEN role is persisted with generated ID")
        void shouldSaveNewRole() {
            // GIVEN
            Role newRole = Role.builder()
                    .name("MODERATOR")
                    .description("Moderator role")
                    .build();

            // WHEN
            Role savedRole = roleRepository.save(newRole);

            // THEN
            assertThat(savedRole.getId()).isNotNull();
            assertThat(savedRole.getName()).isEqualTo("MODERATOR");
        }

        @Test
        @DisplayName("GIVEN existing role WHEN findById is called THEN returns the role")
        void shouldFindRoleById() {
            // GIVEN
            Long roleId = adminRole.getId();

            // WHEN
            Optional<Role> result = roleRepository.findById(roleId);

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("ADMIN");
        }

        @Test
        @DisplayName("GIVEN existing role WHEN delete is called THEN role is removed")
        void shouldDeleteRole() {
            // GIVEN
            Role roleToDelete = Role.builder()
                    .name("TEMP_ROLE")
                    .description("Temporary role")
                    .build();
            roleToDelete = roleRepository.save(roleToDelete);
            Long roleId = roleToDelete.getId();

            // WHEN
            roleRepository.deleteById(roleId);

            // THEN
            assertThat(roleRepository.findById(roleId)).isEmpty();
        }

        @Test
        @DisplayName("GIVEN multiple roles WHEN findAll is called THEN returns all roles")
        void shouldFindAllRoles() {
            // GIVEN - roles already persisted in setUp

            // WHEN
            var allRoles = roleRepository.findAll();

            // THEN
            assertThat(allRoles).hasSizeGreaterThanOrEqualTo(2);
            assertThat(allRoles).extracting(Role::getName)
                    .contains("ADMIN", "USER");
        }

        @Test
        @DisplayName("GIVEN role with new permission WHEN save is called THEN updates role permissions")
        void shouldUpdateRolePermissions() {
            // GIVEN
            Optional<Role> foundRole = roleRepository.findByName("USER");
            assertThat(foundRole).isPresent();
            Role role = foundRole.get();

            Permission newPermission = Permission.builder()
                    .name("DELETE_DATA")
                    .resource("data")
                    .action("delete")
                    .build();
            newPermission = permissionRepository.save(newPermission);

            role.getPermissions().add(newPermission);

            // WHEN
            roleRepository.save(role);

            // THEN
            Optional<Role> updatedRole = roleRepository.findByName("USER");
            assertThat(updatedRole).isPresent();
            assertThat(updatedRole.get().getPermissions()).hasSize(2);
        }
    }

    @Nested
    @DisplayName("Role Without Permissions Tests")
    class RoleWithoutPermissionsTests {

        @Test
        @DisplayName("GIVEN role without permissions WHEN save is called THEN persists successfully")
        void shouldSaveRoleWithoutPermissions() {
            // GIVEN
            Role roleWithoutPermissions = Role.builder()
                    .name("GUEST")
                    .description("Guest role with no permissions")
                    .build();

            // WHEN
            Role savedRole = roleRepository.save(roleWithoutPermissions);

            // THEN
            assertThat(savedRole.getId()).isNotNull();
            assertThat(savedRole.getPermissions()).isNullOrEmpty();
        }

        @Test
        @DisplayName("GIVEN role without permissions WHEN findByName is called THEN returns role with empty permissions")
        void shouldFindRoleWithEmptyPermissions() {
            // GIVEN
            Role guestRole = Role.builder()
                    .name("GUEST")
                    .description("Guest role")
                    .build();
            roleRepository.save(guestRole);

            // WHEN
            Optional<Role> result = roleRepository.findByName("GUEST");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getPermissions()).isNullOrEmpty();
        }
    }
}
