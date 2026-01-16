package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.exception.InvalidPasswordException;
import identityaccessmanagement.example.Identity.Access.Management.exception.InvalidTokenException;
import identityaccessmanagement.example.Identity.Access.Management.exception.ResourceNotFoundException;
import identityaccessmanagement.example.Identity.Access.Management.model.PasswordResetToken;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.PasswordResetTokenRepository;
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
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("PasswordService Tests")
class PasswordServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @InjectMocks
    private PasswordService passwordService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    @Captor
    private ArgumentCaptor<PasswordResetToken> tokenCaptor;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedOldPassword")
                .enabled(true)
                .isLocked(false)
                .build();
    }

    @Nested
    @DisplayName("createPasswordResetToken Tests")
    class CreatePasswordResetTokenTests {

        @Test
        @DisplayName("GIVEN valid email WHEN createPasswordResetToken is called THEN returns token and saves reset token")
        void shouldCreatePasswordResetTokenSuccessfully() {
            // GIVEN
            String email = "test@example.com";
            given(userRepository.findByEmail(email)).willReturn(Optional.of(testUser));
            given(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                    .willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            String token = passwordService.createPasswordResetToken(email);

            // THEN
            assertThat(token).isNotNull();
            assertThat(token).isNotEmpty();

            // Verification - old tokens invalidated first
            verify(passwordResetTokenRepository).invalidateAllUserTokens(testUser);

            // ArgumentCaptor - verify token was saved with correct data
            verify(passwordResetTokenRepository).save(tokenCaptor.capture());
            PasswordResetToken savedToken = tokenCaptor.getValue();
            assertThat(savedToken.getUser()).isEqualTo(testUser);
            assertThat(savedToken.getTokenHash()).isNotNull();
            assertThat(savedToken.getExpiresAt()).isAfter(LocalDateTime.now());
            assertThat(savedToken.getIsUsed()).isFalse();
        }

        @Test
        @DisplayName("GIVEN non-existent email WHEN createPasswordResetToken is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenEmailNotFound() {
            // GIVEN
            String nonExistentEmail = "nonexistent@example.com";
            given(userRepository.findByEmail(nonExistentEmail)).willReturn(Optional.empty());

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> passwordService.createPasswordResetToken(nonExistentEmail))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("email");

            // Verification - nothing should be saved or invalidated
            verify(passwordResetTokenRepository, never()).invalidateAllUserTokens(any());
            verify(passwordResetTokenRepository, never()).save(any());
        }

        @Test
        @DisplayName("GIVEN valid email WHEN createPasswordResetToken is called THEN invalidates existing tokens first")
        void shouldInvalidateExistingTokensBeforeCreatingNew() {
            // GIVEN
            String email = "test@example.com";
            given(userRepository.findByEmail(email)).willReturn(Optional.of(testUser));
            given(passwordResetTokenRepository.save(any(PasswordResetToken.class)))
                    .willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            passwordService.createPasswordResetToken(email);

            // THEN - Verify order of operations
            var inOrder = inOrder(passwordResetTokenRepository);
            inOrder.verify(passwordResetTokenRepository).invalidateAllUserTokens(testUser);
            inOrder.verify(passwordResetTokenRepository).save(any(PasswordResetToken.class));
        }
    }

    @Nested
    @DisplayName("resetPassword Tests")
    class ResetPasswordTests {

        @Test
        @DisplayName("GIVEN valid token WHEN resetPassword is called THEN updates password and deletes token")
        void shouldResetPasswordSuccessfully() {
            // GIVEN
            String token = "valid-reset-token";
            String newPassword = "newSecurePassword123";
            String encodedNewPassword = "encodedNewPassword";

            PasswordResetToken resetToken = PasswordResetToken.builder()
                    .id(1L)
                    .user(testUser)
                    .tokenHash("hashedToken")
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .isUsed(false)
                    .build();

            given(passwordResetTokenRepository.findByTokenHash(anyString())).willReturn(Optional.of(resetToken));
            given(passwordEncoder.encode(newPassword)).willReturn(encodedNewPassword);
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            passwordService.resetPassword(token, newPassword);

            // THEN - ArgumentCaptor to verify password was updated
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getPassword()).isEqualTo(encodedNewPassword);

            // Verification - token should be deleted after use
            verify(passwordResetTokenRepository).delete(resetToken);
        }

        @Test
        @DisplayName("GIVEN invalid token WHEN resetPassword is called THEN throws InvalidTokenException")
        void shouldThrowExceptionWhenTokenNotFound() {
            // GIVEN
            String invalidToken = "invalid-token";
            given(passwordResetTokenRepository.findByTokenHash(anyString())).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> passwordService.resetPassword(invalidToken, "newPassword"))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid password reset token");

            // Verification - no password update should occur
            verify(userRepository, never()).save(any());
            verify(passwordResetTokenRepository, never()).delete(any());
        }

        @Test
        @DisplayName("GIVEN expired token WHEN resetPassword is called THEN throws InvalidTokenException")
        void shouldThrowExceptionWhenTokenExpired() {
            // GIVEN
            String token = "expired-token";
            PasswordResetToken expiredToken = PasswordResetToken.builder()
                    .id(1L)
                    .user(testUser)
                    .tokenHash("hashedToken")
                    .expiresAt(LocalDateTime.now().minusHours(1)) // Expired
                    .isUsed(false)
                    .build();

            given(passwordResetTokenRepository.findByTokenHash(anyString())).willReturn(Optional.of(expiredToken));

            // WHEN/THEN
            assertThatThrownBy(() -> passwordService.resetPassword(token, "newPassword"))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("expired");

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("GIVEN already used token WHEN resetPassword is called THEN throws InvalidTokenException")
        void shouldThrowExceptionWhenTokenAlreadyUsed() {
            // GIVEN
            String token = "used-token";
            PasswordResetToken usedToken = PasswordResetToken.builder()
                    .id(1L)
                    .user(testUser)
                    .tokenHash("hashedToken")
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .isUsed(true) // Already used
                    .build();

            given(passwordResetTokenRepository.findByTokenHash(anyString())).willReturn(Optional.of(usedToken));

            // WHEN/THEN
            assertThatThrownBy(() -> passwordService.resetPassword(token, "newPassword"))
                    .isInstanceOf(InvalidTokenException.class);

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("changePassword Tests")
    class ChangePasswordTests {

        @Test
        @DisplayName("GIVEN correct current password WHEN changePassword is called THEN updates to new password")
        void shouldChangePasswordSuccessfully() {
            // GIVEN
            String username = "testuser";
            String currentPassword = "currentPassword";
            String newPassword = "newPassword123";
            String encodedNewPassword = "encodedNewPassword";
            String originalEncodedPassword = testUser.getPassword(); // Capture before modification

            given(userRepository.findByUsername(username)).willReturn(Optional.of(testUser));
            given(passwordEncoder.matches(currentPassword, originalEncodedPassword)).willReturn(true);
            given(passwordEncoder.encode(newPassword)).willReturn(encodedNewPassword);
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            passwordService.changePassword(username, currentPassword, newPassword);

            // THEN - ArgumentCaptor to verify password was updated
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getPassword()).isEqualTo(encodedNewPassword);

            // Verification - use captured original password since testUser is mutable
            verify(passwordEncoder).matches(currentPassword, originalEncodedPassword);
            verify(passwordEncoder).encode(newPassword);
        }

        @Test
        @DisplayName("GIVEN non-existent username WHEN changePassword is called THEN throws ResourceNotFoundException")
        void shouldThrowExceptionWhenUserNotFound() {
            // GIVEN
            String nonExistentUsername = "nonexistent";
            given(userRepository.findByUsername(nonExistentUsername)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> passwordService.changePassword(nonExistentUsername, "current", "new"))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("username");

            verify(passwordEncoder, never()).matches(anyString(), anyString());
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("GIVEN incorrect current password WHEN changePassword is called THEN throws InvalidPasswordException")
        void shouldThrowExceptionWhenCurrentPasswordIncorrect() {
            // GIVEN
            String username = "testuser";
            String wrongCurrentPassword = "wrongPassword";
            String newPassword = "newPassword123";

            given(userRepository.findByUsername(username)).willReturn(Optional.of(testUser));
            given(passwordEncoder.matches(wrongCurrentPassword, testUser.getPassword())).willReturn(false);

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> passwordService.changePassword(username, wrongCurrentPassword, newPassword))
                    .isInstanceOf(InvalidPasswordException.class)
                    .hasMessageContaining("Current password is incorrect");

            // Verification - new password should not be encoded or saved
            verify(passwordEncoder, never()).encode(anyString());
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("GIVEN valid credentials WHEN changePassword is called THEN verifies password matching before encoding")
        void shouldVerifyCurrentPasswordBeforeChanging() {
            // GIVEN
            String username = "testuser";
            String currentPassword = "currentPassword";
            String newPassword = "newPassword123";
            String originalEncodedPassword = testUser.getPassword(); // Capture before modification

            given(userRepository.findByUsername(username)).willReturn(Optional.of(testUser));
            given(passwordEncoder.matches(currentPassword, originalEncodedPassword)).willReturn(true);
            given(passwordEncoder.encode(newPassword)).willReturn("encodedNew");
            given(userRepository.save(any(User.class))).willReturn(testUser);

            // WHEN
            passwordService.changePassword(username, currentPassword, newPassword);

            // THEN - Verify order: match first, then encode (use captured original password)
            var inOrder = inOrder(passwordEncoder);
            inOrder.verify(passwordEncoder).matches(currentPassword, originalEncodedPassword);
            inOrder.verify(passwordEncoder).encode(newPassword);
        }
    }
}
