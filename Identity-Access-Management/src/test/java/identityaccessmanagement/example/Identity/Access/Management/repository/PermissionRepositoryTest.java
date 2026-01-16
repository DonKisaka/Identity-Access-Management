package identityaccessmanagement.example.Identity.Access.Management.repository;

import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest
@DisplayName("PermissionRepository Tests")
class PermissionRepositoryTest {

    @Autowired
    private PermissionRepository permissionRepository;

    private Permission readPermission;
    private Permission writePermission;
    private Permission deletePermission;

    @BeforeEach
    void setUp() {
        // Clear previous test data
        permissionRepository.deleteAll();

        readPermission = Permission.builder()
                .name("READ_USERS")
                .resource("users")
                .action("read")
                .description("Permission to read users")
                .build();
        readPermission = permissionRepository.save(readPermission);

        writePermission = Permission.builder()
                .name("WRITE_USERS")
                .resource("users")
                .action("write")
                .description("Permission to write users")
                .build();
        writePermission = permissionRepository.save(writePermission);

        deletePermission = Permission.builder()
                .name("DELETE_USERS")
                .resource("users")
                .action("delete")
                .description("Permission to delete users")
                .build();
        deletePermission = permissionRepository.save(deletePermission);
    }

    @Nested
    @DisplayName("findByName Tests")
    class FindByNameTests {

        @Test
        @DisplayName("GIVEN permission exists WHEN findByName is called THEN returns the permission")
        void shouldFindPermissionByName() {
            // GIVEN - permissions already persisted in setUp

            // WHEN
            Optional<Permission> result = permissionRepository.findByName("READ_USERS");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("READ_USERS");
            assertThat(result.get().getResource()).isEqualTo("users");
            assertThat(result.get().getAction()).isEqualTo("read");
        }

        @Test
        @DisplayName("GIVEN permission doesn't exist WHEN findByName is called THEN returns empty")
        void shouldReturnEmptyWhenPermissionNotFound() {
            // GIVEN - no permission with this name

            // WHEN
            Optional<Permission> result = permissionRepository.findByName("NONEXISTENT_PERMISSION");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN permission name is case-sensitive WHEN findByName with different case THEN returns empty")
        void shouldBeCaseSensitiveForPermissionName() {
            // GIVEN - permission with uppercase name

            // WHEN
            Optional<Permission> result = permissionRepository.findByName("read_users");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN multiple permissions WHEN findByName for each THEN returns correct permission")
        void shouldFindCorrectPermissionAmongMultiple() {
            // GIVEN - multiple permissions persisted

            // WHEN
            Optional<Permission> read = permissionRepository.findByName("READ_USERS");
            Optional<Permission> write = permissionRepository.findByName("WRITE_USERS");
            Optional<Permission> delete = permissionRepository.findByName("DELETE_USERS");

            // THEN
            assertThat(read).isPresent();
            assertThat(read.get().getAction()).isEqualTo("read");

            assertThat(write).isPresent();
            assertThat(write.get().getAction()).isEqualTo("write");

            assertThat(delete).isPresent();
            assertThat(delete.get().getAction()).isEqualTo("delete");
        }
    }

    @Nested
    @DisplayName("CRUD Operations Tests")
    class CrudOperationsTests {

        @Test
        @DisplayName("GIVEN new permission WHEN save is called THEN permission is persisted with generated ID")
        void shouldSaveNewPermission() {
            // GIVEN
            Permission newPermission = Permission.builder()
                    .name("UPDATE_USERS")
                    .resource("users")
                    .action("update")
                    .description("Permission to update users")
                    .build();

            // WHEN
            Permission savedPermission = permissionRepository.save(newPermission);

            // THEN
            assertThat(savedPermission.getId()).isNotNull();
            assertThat(savedPermission.getName()).isEqualTo("UPDATE_USERS");
        }

        @Test
        @DisplayName("GIVEN existing permission WHEN findById is called THEN returns the permission")
        void shouldFindPermissionById() {
            // GIVEN
            Long permissionId = readPermission.getId();

            // WHEN
            Optional<Permission> result = permissionRepository.findById(permissionId);

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("READ_USERS");
        }

        @Test
        @DisplayName("GIVEN existing permission WHEN delete is called THEN permission is removed")
        void shouldDeletePermission() {
            // GIVEN
            Permission tempPermission = Permission.builder()
                    .name("TEMP_PERMISSION")
                    .resource("temp")
                    .action("temp")
                    .build();
            tempPermission = permissionRepository.save(tempPermission);
            Long permissionId = tempPermission.getId();

            // WHEN
            permissionRepository.deleteById(permissionId);

            // THEN
            assertThat(permissionRepository.findById(permissionId)).isEmpty();
        }

        @Test
        @DisplayName("GIVEN multiple permissions WHEN findAll is called THEN returns all permissions")
        void shouldFindAllPermissions() {
            // GIVEN - permissions already persisted in setUp

            // WHEN
            var allPermissions = permissionRepository.findAll();

            // THEN
            assertThat(allPermissions).hasSizeGreaterThanOrEqualTo(3);
            assertThat(allPermissions).extracting(Permission::getName)
                    .contains("READ_USERS", "WRITE_USERS", "DELETE_USERS");
        }

        @Test
        @DisplayName("GIVEN existing permission WHEN update is called THEN permission is updated")
        void shouldUpdatePermission() {
            // GIVEN
            Optional<Permission> foundPermission = permissionRepository.findByName("READ_USERS");
            assertThat(foundPermission).isPresent();
            Permission permission = foundPermission.get();
            permission.setDescription("Updated description for read users");

            // WHEN
            permissionRepository.save(permission);

            // THEN
            Optional<Permission> updatedPermission = permissionRepository.findByName("READ_USERS");
            assertThat(updatedPermission).isPresent();
            assertThat(updatedPermission.get().getDescription()).isEqualTo("Updated description for read users");
        }
    }

    @Nested
    @DisplayName("Permission with Null Fields Tests")
    class PermissionWithNullFieldsTests {

        @Test
        @DisplayName("GIVEN permission with null description WHEN save is called THEN persists successfully")
        void shouldSavePermissionWithNullDescription() {
            // GIVEN
            Permission permissionWithNullDesc = Permission.builder()
                    .name("BASIC_PERMISSION")
                    .resource("basic")
                    .action("access")
                    .description(null)
                    .build();

            // WHEN
            Permission savedPermission = permissionRepository.save(permissionWithNullDesc);

            // THEN
            assertThat(savedPermission.getId()).isNotNull();
            assertThat(savedPermission.getDescription()).isNull();
        }

        @Test
        @DisplayName("GIVEN permission with all optional fields null WHEN findByName is called THEN returns permission")
        void shouldFindPermissionWithNullOptionalFields() {
            // GIVEN
            Permission minimalPermission = Permission.builder()
                    .name("MINIMAL_PERMISSION")
                    .build();
            permissionRepository.save(minimalPermission);

            // WHEN
            Optional<Permission> result = permissionRepository.findByName("MINIMAL_PERMISSION");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getResource()).isNull();
            assertThat(result.get().getAction()).isNull();
            assertThat(result.get().getDescription()).isNull();
        }
    }
}
