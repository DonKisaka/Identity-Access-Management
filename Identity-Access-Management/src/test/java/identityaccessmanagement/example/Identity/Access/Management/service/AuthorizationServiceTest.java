package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.exception.ResourceNotFoundException;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.RoleRepository;
import identityaccessmanagement.example.Identity.Access.Management.repository.UserRepository;
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
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthorizationService authorizationService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    private User testUser;
    private Role userRole;
    private Role adminRole;
    private Role moderatorRole;

    @BeforeEach
    void setUp() {
        userRole = Role.builder()
                .id(1L)
                .name("USER")
                .description("Standard user role")
                .permissions(Set.of())
                .build();

        adminRole = Role.builder()
                .id(2L)
                .name("ADMIN")
                .description("Administrator role")
                .permissions(Set.of())
                .build();

        moderatorRole = Role.builder()
                .id(3L)
                .name("MODERATOR")
                .description("Moderator role")
                .permissions(Set.of())
                .build();

        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .isLocked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
    }

    @Nested
    class AssignRoleToUserTests {

        @Test
        void shouldAssignRoleToUserSuccessfully() {
            // GIVEN
            Long userId = 1L;
            String roleName = "ADMIN";

            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(roleRepository.findByName(roleName)).willReturn(Optional.of(adminRole));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            authorizationService.assignRoleToUser(userId, roleName);

            // THEN - ArgumentCaptor to verify role was added
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getRoles()).hasSize(2);
            assertThat(savedUser.getRoles()).extracting(Role::getName)
                    .containsExactlyInAnyOrder("USER", "ADMIN");
        }

        @Test
        void shouldNotDuplicateExistingRole() {
            // GIVEN
            Long userId = 1L;
            String roleName = "USER"; // User already has this role

            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(roleRepository.findByName(roleName)).willReturn(Optional.of(userRole));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            authorizationService.assignRoleToUser(userId, roleName);

            // THEN - Role count should remain the same (Set doesn't allow duplicates)
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getRoles()).hasSize(1);
            assertThat(savedUser.getRoles()).extracting(Role::getName).containsOnly("USER");
        }

        @Test
        void shouldThrowExceptionWhenUserNotFound() {
            // GIVEN
            Long nonExistentUserId = 999L;
            given(userRepository.findById(nonExistentUserId)).willReturn(Optional.empty());

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> authorizationService.assignRoleToUser(nonExistentUserId, "ADMIN"))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("id");

            // Verification - role lookup and save should never happen
            verify(roleRepository, never()).findByName(anyString());
            verify(userRepository, never()).save(any());
        }

        @Test
        void shouldThrowExceptionWhenRoleNotFound() {
            // GIVEN
            Long userId = 1L;
            String nonExistentRole = "SUPERADMIN";

            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(roleRepository.findByName(nonExistentRole)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authorizationService.assignRoleToUser(userId, nonExistentRole))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Role")
                    .hasMessageContaining("name");

            verify(userRepository, never()).save(any());
        }

        @Test
        void shouldAccumulateMultipleRoles() {
            // GIVEN
            Long userId = 1L;

            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(roleRepository.findByName("ADMIN")).willReturn(Optional.of(adminRole));
            given(roleRepository.findByName("MODERATOR")).willReturn(Optional.of(moderatorRole));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN - Assign ADMIN first
            authorizationService.assignRoleToUser(userId, "ADMIN");

            // THEN - Verify ADMIN was added
            verify(userRepository).save(userCaptor.capture());
            User afterFirstAssignment = userCaptor.getValue();
            assertThat(afterFirstAssignment.getRoles()).hasSize(2);

            // WHEN - Assign MODERATOR
            authorizationService.assignRoleToUser(userId, "MODERATOR");

            // THEN - Verify MODERATOR was also added
            verify(userRepository, times(2)).save(userCaptor.capture());
            User afterSecondAssignment = userCaptor.getValue();
            assertThat(afterSecondAssignment.getRoles()).hasSize(3);
        }
    }

    @Nested
    class RemoveRoleFromUserTests {

        @Test
        void shouldRemoveRoleFromUserSuccessfully() {
            // GIVEN
            User userWithMultipleRoles = User.builder()
                    .id(1L)
                    .username("testuser")
                    .email("test@example.com")
                    .roles(new HashSet<>(Set.of(userRole, adminRole)))
                    .build();

            Long userId = 1L;
            String roleName = "ADMIN";

            given(userRepository.findById(userId)).willReturn(Optional.of(userWithMultipleRoles));
            given(roleRepository.findByName(roleName)).willReturn(Optional.of(adminRole));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            authorizationService.removeRoleFromUser(userId, roleName);

            // THEN - ArgumentCaptor to verify role was removed
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getRoles()).hasSize(1);
            assertThat(savedUser.getRoles()).extracting(Role::getName).containsOnly("USER");
        }

        @Test
        void shouldCompleteWithoutErrorWhenUserDoesntHaveRole() {
            // GIVEN
            Long userId = 1L;
            String roleName = "ADMIN"; // testUser only has USER role

            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(roleRepository.findByName(roleName)).willReturn(Optional.of(adminRole));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN - Should not throw
            authorizationService.removeRoleFromUser(userId, roleName);

            // THEN - User roles should remain unchanged
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getRoles()).hasSize(1);
            assertThat(savedUser.getRoles()).extracting(Role::getName).containsOnly("USER");
        }

        @Test
        void shouldThrowExceptionWhenUserNotFoundForRemove() {
            // GIVEN
            Long nonExistentUserId = 999L;
            given(userRepository.findById(nonExistentUserId)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authorizationService.removeRoleFromUser(nonExistentUserId, "USER"))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User");

            verify(roleRepository, never()).findByName(anyString());
            verify(userRepository, never()).save(any());
        }

        @Test
        void shouldThrowExceptionWhenRoleNotFoundForRemove() {
            // GIVEN
            Long userId = 1L;
            String nonExistentRole = "NONEXISTENT";

            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(roleRepository.findByName(nonExistentRole)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authorizationService.removeRoleFromUser(userId, nonExistentRole))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Role");

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    class GetUserRolesTests {

        @Test
        void shouldReturnUserRoles() {
            // GIVEN
            User userWithMultipleRoles = User.builder()
                    .id(1L)
                    .username("testuser")
                    .roles(new HashSet<>(Set.of(userRole, adminRole, moderatorRole)))
                    .build();

            Long userId = 1L;
            given(userRepository.findById(userId)).willReturn(Optional.of(userWithMultipleRoles));

            // WHEN
            Set<String> roles = authorizationService.getUserRoles(userId);

            // THEN
            assertThat(roles).hasSize(3);
            assertThat(roles).containsExactlyInAnyOrder("USER", "ADMIN", "MODERATOR");

            // Verification
            verify(userRepository).findById(userId);
        }

        @Test
        void shouldReturnSingleRole() {
            // GIVEN
            Long userId = 1L;
            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));

            // WHEN
            Set<String> roles = authorizationService.getUserRoles(userId);

            // THEN
            assertThat(roles).hasSize(1);
            assertThat(roles).containsOnly("USER");
        }

        @Test
        void shouldReturnEmptySetWhenNoRoles() {
            // GIVEN
            User userWithNoRoles = User.builder()
                    .id(1L)
                    .username("newuser")
                    .roles(new HashSet<>())
                    .build();

            Long userId = 1L;
            given(userRepository.findById(userId)).willReturn(Optional.of(userWithNoRoles));

            // WHEN
            Set<String> roles = authorizationService.getUserRoles(userId);

            // THEN
            assertThat(roles).isEmpty();
        }

        @Test
        void shouldThrowExceptionWhenUserNotFoundForGetRoles() {
            // GIVEN
            Long nonExistentUserId = 999L;
            given(userRepository.findById(nonExistentUserId)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authorizationService.getUserRoles(nonExistentUserId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("id");
        }
    }
}
