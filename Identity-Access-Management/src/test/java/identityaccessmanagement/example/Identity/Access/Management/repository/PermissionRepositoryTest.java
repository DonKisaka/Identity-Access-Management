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
        void shouldReturnEmptyWhenPermissionNotFound() {
            // GIVEN - no permission with this name

            // WHEN
            Optional<Permission> result = permissionRepository.findByName("NONEXISTENT_PERMISSION");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        void shouldBeCaseSensitiveForPermissionName() {
            // GIVEN - permission with uppercase name

            // WHEN
            Optional<Permission> result = permissionRepository.findByName("read_users");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
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
    class PermissionWithNullFieldsTests {

        @Test
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
