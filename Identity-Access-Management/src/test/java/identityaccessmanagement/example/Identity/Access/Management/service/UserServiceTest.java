package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.dto.UserResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.ResourceNotFoundException;
import identityaccessmanagement.example.Identity.Access.Management.mapper.UserMapper;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserMapper userMapper;

    @InjectMocks
    private UserService userService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    private User testUser;
    private UserResponseDto testUserResponse;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Common test fixtures
        userRole = Role.builder()
                .id(1L)
                .name("USER")
                .description("Standard user role")
                .permissions(Set.of())
                .build();

        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .roles(Set.of(userRole))
                .build();

        testUserResponse = new UserResponseDto(
                1L,
                "testuser",
                "test@example.com",
                true,
                Set.of("USER"),
                Set.of()
        );
    }

    @Nested
    @DisplayName("getUserByUsername Tests")
    class GetUserByUsernameTests {

        @Test
        @DisplayName("GIVEN a valid username WHEN getUserByUsername is called THEN returns user response")
        void shouldReturnUserWhenUsernameExists() {
            // GIVEN
            String username = "testuser";
            given(userRepository.findByUsernameWithRoles(username)).willReturn(Optional.of(testUser));
            given(userMapper.toResponse(testUser)).willReturn(testUserResponse);

            // WHEN
            UserResponseDto result = userService.getUserByUsername(username);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.username()).isEqualTo(username);
            assertThat(result.email()).isEqualTo("test@example.com");
            assertThat(result.roles()).contains("USER");

            // Verification: Ensure repository was called exactly once
            verify(userRepository, times(1)).findByUsernameWithRoles(username);
            verify(userMapper, times(1)).toResponse(testUser);
        }

        @Test
        @DisplayName("GIVEN a non-existent username WHEN getUserByUsername is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenUsernameNotFound() {
            // GIVEN
            String nonExistentUsername = "nonexistent";
            given(userRepository.findByUsernameWithRoles(nonExistentUsername)).willReturn(Optional.empty());

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> userService.getUserByUsername(nonExistentUsername))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("username")
                    .hasMessageContaining(nonExistentUsername);

            // Verification: Ensure mapper was never called on failure
            verify(userMapper, never()).toResponse(any());
        }
    }

    @Nested
    @DisplayName("getUserById Tests")
    class GetUserByIdTests {

        @Test
        @DisplayName("GIVEN a valid ID WHEN getUserById is called THEN returns user response")
        void shouldReturnUserWhenIdExists() {
            // GIVEN
            Long userId = 1L;
            given(userRepository.findById(userId)).willReturn(Optional.of(testUser));
            given(userMapper.toResponse(testUser)).willReturn(testUserResponse);

            // WHEN
            UserResponseDto result = userService.getUserById(userId);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.id()).isEqualTo(userId);
            verify(userRepository).findById(userId);
        }

        @Test
        @DisplayName("GIVEN a non-existent ID WHEN getUserById is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenIdNotFound() {
            // GIVEN
            Long nonExistentId = 999L;
            given(userRepository.findById(nonExistentId)).willReturn(Optional.empty());

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> userService.getUserById(nonExistentId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("id");

            verify(userMapper, never()).toResponse(any());
        }
    }

    @Nested
    @DisplayName("getAllUsers Tests")
    class GetAllUsersTests {

        @Test
        @DisplayName("GIVEN users exist WHEN getAllUsers is called THEN returns paginated users")
        void shouldReturnPaginatedUsers() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);
            User secondUser = User.builder()
                    .id(2L)
                    .username("seconduser")
                    .email("second@example.com")
                    .build();
            UserResponseDto secondResponse = new UserResponseDto(2L, "seconduser", "second@example.com", true, Set.of(), Set.of());

            Page<User> userPage = new PageImpl<>(List.of(testUser, secondUser), pageable, 2);
            given(userRepository.findAll(pageable)).willReturn(userPage);
            given(userMapper.toResponse(testUser)).willReturn(testUserResponse);
            given(userMapper.toResponse(secondUser)).willReturn(secondResponse);

            // WHEN
            Page<UserResponseDto> result = userService.getAllUsers(pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(2);
            assertThat(result.getTotalElements()).isEqualTo(2);
            verify(userRepository).findAll(pageable);
        }

        @Test
        @DisplayName("GIVEN no users exist WHEN getAllUsers is called THEN returns empty page")
        void shouldReturnEmptyPageWhenNoUsers() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);
            Page<User> emptyPage = new PageImpl<>(List.of(), pageable, 0);
            given(userRepository.findAll(pageable)).willReturn(emptyPage);

            // WHEN
            Page<UserResponseDto> result = userService.getAllUsers(pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
            assertThat(result.getTotalElements()).isZero();
        }
    }

    @Nested
    @DisplayName("unlockUser Tests")
    class UnlockUserTests {

        @Test
        @DisplayName("GIVEN a locked user WHEN unlockUser is called THEN user is unlocked and saved")
        void shouldUnlockUserAndSave() {
            // GIVEN
            User lockedUser = User.builder()
                    .id(1L)
                    .username("lockeduser")
                    .email("locked@example.com")
                    .isLocked(true)
                    .failedLoginAttempts(5)
                    .build();
            given(userRepository.findById(1L)).willReturn(Optional.of(lockedUser));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            userService.unlockUser(1L);

            // THEN - ArgumentCaptor to verify the state of saved user
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getIsLocked()).isFalse();
            assertThat(savedUser.getFailedLoginAttempts()).isZero();
        }

        @Test
        @DisplayName("GIVEN a non-existent user ID WHEN unlockUser is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenUserNotFoundForUnlock() {
            // GIVEN
            Long nonExistentId = 999L;
            given(userRepository.findById(nonExistentId)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> userService.unlockUser(nonExistentId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User");

            // Verification: save should never be called
            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("disableUser Tests")
    class DisableUserTests {

        @Test
        @DisplayName("GIVEN an enabled user WHEN disableUser is called THEN user is disabled")
        void shouldDisableUser() {
            // GIVEN
            User enabledUser = User.builder()
                    .id(1L)
                    .username("enableduser")
                    .enabled(true)
                    .build();
            given(userRepository.findById(1L)).willReturn(Optional.of(enabledUser));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            userService.disableUser(1L);

            // THEN - Using ArgumentCaptor
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getEnabled()).isFalse();
        }

        @Test
        @DisplayName("GIVEN a non-existent user ID WHEN disableUser is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenUserNotFoundForDisable() {
            // GIVEN
            given(userRepository.findById(anyLong())).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> userService.disableUser(999L))
                    .isInstanceOf(ResourceNotFoundException.class);

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("enableUser Tests")
    class EnableUserTests {

        @Test
        @DisplayName("GIVEN a disabled user WHEN enableUser is called THEN user is enabled")
        void shouldEnableUser() {
            // GIVEN
            User disabledUser = User.builder()
                    .id(1L)
                    .username("disableduser")
                    .enabled(false)
                    .build();
            given(userRepository.findById(1L)).willReturn(Optional.of(disabledUser));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            userService.enableUser(1L);

            // THEN
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getEnabled()).isTrue();
        }

        @Test
        @DisplayName("GIVEN a non-existent user ID WHEN enableUser is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenUserNotFoundForEnable() {
            // GIVEN
            given(userRepository.findById(anyLong())).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> userService.enableUser(999L))
                    .isInstanceOf(ResourceNotFoundException.class);

            verify(userRepository, never()).save(any());
        }
    }
}
