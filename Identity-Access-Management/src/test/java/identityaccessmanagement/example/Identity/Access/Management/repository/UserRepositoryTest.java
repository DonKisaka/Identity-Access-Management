package identityaccessmanagement.example.Identity.Access.Management.repository;

import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    private User testUser;
    private Role userRole;
    private Permission readPermission;

    @BeforeEach
    void setUp() {
        // clear repositories before each test
        userRepository.deleteAll();
        roleRepository.deleteAll();
        permissionRepository.deleteAll();

        // create test data
        readPermission = Permission.builder()
                .name("READ_USERS")
                .resource("users")
                .action("read")
                .description("Read users permission")
                .build();
        readPermission = permissionRepository.save(readPermission);

        userRole = Role.builder()
                .name("USER")
                .description("Standard user role")
                .permissions(Set.of(readPermission))
                .build();
        userRole = roleRepository.save(userRole);

        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .roles(Set.of(userRole))
                .build();
        testUser = userRepository.save(testUser);
    }

    @Nested
    class FindByEmailTests {

        @Test
        void shouldFindUserByEmail() {
            // GIVEN - user already persisted in setUp

            // WHEN
            Optional<User> result = userRepository.findByEmail("test@example.com");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getUsername()).isEqualTo("testuser");
            assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        void shouldReturnEmptyWhenEmailNotFound() {
            // GIVEN - no user with this email

            // WHEN
            Optional<User> result = userRepository.findByEmail("nonexistent@example.com");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        void shouldBeCaseSensitiveForEmail() {
            // GIVEN - user with lowercase email

            // WHEN
            Optional<User> result = userRepository.findByEmail("TEST@EXAMPLE.COM");

            // THEN
            assertThat(result).isEmpty();
        }
    }

    @Nested
    class FindByUsernameTests {

        @Test
        void shouldFindUserByUsername() {
            // GIVEN - user already persisted

            // WHEN
            Optional<User> result = userRepository.findByUsername("testuser");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        void shouldReturnEmptyWhenUsernameNotFound() {
            // GIVEN - no user with this username

            // WHEN
            Optional<User> result = userRepository.findByUsername("nonexistent");

            // THEN
            assertThat(result).isEmpty();
        }
    }

    @Nested
    class ExistsByUsernameTests {

        @Test
        void shouldReturnTrueWhenUsernameExists() {
            // GIVEN - user already persisted

            // WHEN
            boolean exists = userRepository.existsByUsername("testuser");

            // THEN
            assertThat(exists).isTrue();
        }

        @Test
        void shouldReturnFalseWhenUsernameDoesNotExist() {
            // GIVEN - no user with this username

            // WHEN
            boolean exists = userRepository.existsByUsername("nonexistent");

            // THEN
            assertThat(exists).isFalse();
        }
    }

    @Nested
    class ExistsByEmailTests {

        @Test
        void shouldReturnTrueWhenEmailExists() {
            // GIVEN - user already persisted

            // WHEN
            boolean exists = userRepository.existsByEmail("test@example.com");

            // THEN
            assertThat(exists).isTrue();
        }

        @Test
        void shouldReturnFalseWhenEmailDoesNotExist() {
            // GIVEN - no user with this email

            // WHEN
            boolean exists = userRepository.existsByEmail("nonexistent@example.com");

            // THEN
            assertThat(exists).isFalse();
        }
    }

    @Nested
    class FindByUsernameWithRolesTests {

        @Test
        void shouldFindUserWithRolesEagerlyLoaded() {
            // GIVEN - user with roles already persisted

            // WHEN
            Optional<User> result = userRepository.findByUsernameWithRoles("testuser");

            // THEN
            assertThat(result).isPresent();
            User user = result.get();
            assertThat(user.getRoles()).isNotEmpty();
            assertThat(user.getRoles()).hasSize(1);
            assertThat(user.getRoles().iterator().next().getName()).isEqualTo("USER");
        }

        @Test
        void shouldFindUserWithPermissionsLoaded() {
            // GIVEN - user with roles and permissions already persisted

            // WHEN
            Optional<User> result = userRepository.findByUsernameWithRoles("testuser");

            // THEN
            assertThat(result).isPresent();
            User user = result.get();
            Role role = user.getRoles().iterator().next();
            assertThat(role.getPermissions()).isNotEmpty();
            assertThat(role.getPermissions().iterator().next().getName()).isEqualTo("READ_USERS");
        }

        @Test
        void shouldReturnEmptyWhenUsernameNotFoundWithRoles() {
            // GIVEN - no user with this username

            // WHEN
            Optional<User> result = userRepository.findByUsernameWithRoles("nonexistent");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        void shouldFindUserWithEmptyRoles() {
            // GIVEN - create user without roles
            User userWithoutRoles = User.builder()
                    .username("noroles")
                    .email("noroles@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();
            userRepository.save(userWithoutRoles);

            // WHEN
            Optional<User> result = userRepository.findByUsernameWithRoles("noroles");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getRoles()).isEmpty();
        }
    }
}
