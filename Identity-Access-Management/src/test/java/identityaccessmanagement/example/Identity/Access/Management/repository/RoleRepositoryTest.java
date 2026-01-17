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
    class FindByNameTests {

        @Test
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
        void shouldReturnEmptyWhenRoleNotFound() {
            // GIVEN - no role with this name

            // WHEN
            Optional<Role> result = roleRepository.findByName("SUPERADMIN");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        void shouldBeCaseSensitiveForRoleName() {
            // GIVEN - role with uppercase name

            // WHEN
            Optional<Role> result = roleRepository.findByName("admin");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
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
    class RoleWithoutPermissionsTests {

        @Test
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
