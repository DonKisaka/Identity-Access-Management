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
@DisplayName("UserRepository Tests")
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
        // Clear previous test data
        userRepository.deleteAll();
        roleRepository.deleteAll();
        permissionRepository.deleteAll();

        // Create and persist permission
        readPermission = Permission.builder()
                .name("READ_USERS")
                .resource("users")
                .action("read")
                .description("Read users permission")
                .build();
        readPermission = permissionRepository.save(readPermission);

        // Create and persist role with permission
        userRole = Role.builder()
                .name("USER")
                .description("Standard user role")
                .permissions(Set.of(readPermission))
                .build();
        userRole = roleRepository.save(userRole);

        // Create and persist user with role
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
    @DisplayName("findByEmail Tests")
    class FindByEmailTests {

        @Test
        @DisplayName("GIVEN user exists with email WHEN findByEmail is called THEN returns the user")
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
        @DisplayName("GIVEN no user with email WHEN findByEmail is called THEN returns empty")
        void shouldReturnEmptyWhenEmailNotFound() {
            // GIVEN - no user with this email

            // WHEN
            Optional<User> result = userRepository.findByEmail("nonexistent@example.com");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN email search is case-sensitive WHEN findByEmail with different case THEN returns empty")
        void shouldBeCaseSensitiveForEmail() {
            // GIVEN - user with lowercase email

            // WHEN
            Optional<User> result = userRepository.findByEmail("TEST@EXAMPLE.COM");

            // THEN
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("findByUsername Tests")
    class FindByUsernameTests {

        @Test
        @DisplayName("GIVEN user exists with username WHEN findByUsername is called THEN returns the user")
        void shouldFindUserByUsername() {
            // GIVEN - user already persisted

            // WHEN
            Optional<User> result = userRepository.findByUsername("testuser");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("GIVEN no user with username WHEN findByUsername is called THEN returns empty")
        void shouldReturnEmptyWhenUsernameNotFound() {
            // GIVEN - no user with this username

            // WHEN
            Optional<User> result = userRepository.findByUsername("nonexistent");

            // THEN
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("existsByUsername Tests")
    class ExistsByUsernameTests {

        @Test
        @DisplayName("GIVEN user exists WHEN existsByUsername is called THEN returns true")
        void shouldReturnTrueWhenUsernameExists() {
            // GIVEN - user already persisted

            // WHEN
            boolean exists = userRepository.existsByUsername("testuser");

            // THEN
            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("GIVEN user doesn't exist WHEN existsByUsername is called THEN returns false")
        void shouldReturnFalseWhenUsernameDoesNotExist() {
            // GIVEN - no user with this username

            // WHEN
            boolean exists = userRepository.existsByUsername("nonexistent");

            // THEN
            assertThat(exists).isFalse();
        }
    }

    @Nested
    @DisplayName("existsByEmail Tests")
    class ExistsByEmailTests {

        @Test
        @DisplayName("GIVEN user exists WHEN existsByEmail is called THEN returns true")
        void shouldReturnTrueWhenEmailExists() {
            // GIVEN - user already persisted

            // WHEN
            boolean exists = userRepository.existsByEmail("test@example.com");

            // THEN
            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("GIVEN user doesn't exist WHEN existsByEmail is called THEN returns false")
        void shouldReturnFalseWhenEmailDoesNotExist() {
            // GIVEN - no user with this email

            // WHEN
            boolean exists = userRepository.existsByEmail("nonexistent@example.com");

            // THEN
            assertThat(exists).isFalse();
        }
    }

    @Nested
    @DisplayName("findByUsernameWithRoles Tests")
    class FindByUsernameWithRolesTests {

        @Test
        @DisplayName("GIVEN user with roles WHEN findByUsernameWithRoles is called THEN returns user with roles eagerly loaded")
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
        @DisplayName("GIVEN user with roles and permissions WHEN findByUsernameWithRoles is called THEN returns user with permissions loaded")
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
        @DisplayName("GIVEN no user with username WHEN findByUsernameWithRoles is called THEN returns empty")
        void shouldReturnEmptyWhenUsernameNotFoundWithRoles() {
            // GIVEN - no user with this username

            // WHEN
            Optional<User> result = userRepository.findByUsernameWithRoles("nonexistent");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN user without roles WHEN findByUsernameWithRoles is called THEN returns user with empty roles")
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

    @Nested
    @DisplayName("CRUD Operations Tests")
    class CrudOperationsTests {

        @Test
        @DisplayName("GIVEN new user WHEN save is called THEN user is persisted with generated ID")
        void shouldSaveNewUser() {
            // GIVEN
            User newUser = User.builder()
                    .username("newuser")
                    .email("new@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();

            // WHEN
            User savedUser = userRepository.save(newUser);

            // THEN
            assertThat(savedUser.getId()).isNotNull();
            assertThat(savedUser.getUsername()).isEqualTo("newuser");
        }

        @Test
        @DisplayName("GIVEN existing user WHEN delete is called THEN user is removed")
        void shouldDeleteUser() {
            // GIVEN
            Long userId = testUser.getId();
            assertThat(userRepository.findById(userId)).isPresent();

            // WHEN
            userRepository.deleteById(userId);

            // THEN
            assertThat(userRepository.findById(userId)).isEmpty();
        }

        @Test
        @DisplayName("GIVEN multiple users WHEN findAll is called THEN returns all users")
        void shouldFindAllUsers() {
            // GIVEN - add another user
            User anotherUser = User.builder()
                    .username("another")
                    .email("another@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();
            userRepository.save(anotherUser);

            // WHEN
            var allUsers = userRepository.findAll();

            // THEN
            assertThat(allUsers).hasSizeGreaterThanOrEqualTo(2);
        }
    }
}
