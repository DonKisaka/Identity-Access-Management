package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.config.JwtService;
import identityaccessmanagement.example.Identity.Access.Management.dto.AuthenticationResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.CreateUserDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.LoginUserDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.*;
import identityaccessmanagement.example.Identity.Access.Management.model.RefreshToken;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.RefreshTokenRepository;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    @Captor
    private ArgumentCaptor<RefreshToken> refreshTokenCaptor;

    @Captor
    private ArgumentCaptor<UsernamePasswordAuthenticationToken> authTokenCaptor;

    private User testUser;
    private Role userRole;
    private static final String IP_ADDRESS = "192.168.1.1";
    private static final String USER_AGENT = "Mozilla/5.0";
    private static final String ACCESS_TOKEN = "access.token.here";
    private static final String REFRESH_TOKEN = "refresh.token.here";
    private static final Long EXPIRATION = 3600000L;

    @BeforeEach
    void setUp() {
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
    }

    @Nested
    class SignUpTests {

        @Test
        void shouldSignUpSuccessfully() {
            // GIVEN
            CreateUserDto createUserDto = new CreateUserDto("newuser", "newuser@example.com", "password123");

            given(userRepository.existsByEmail("newuser@example.com")).willReturn(false);
            given(userRepository.existsByUsername("newuser")).willReturn(false);
            given(roleRepository.findByName("USER")).willReturn(Optional.of(userRole));
            given(passwordEncoder.encode("password123")).willReturn("encodedPassword");
            given(userRepository.save(any(User.class))).willAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(2L);
                return user;
            });
            given(jwtService.generateToken(any(User.class))).willReturn(ACCESS_TOKEN);
            given(jwtService.generateRefreshToken(any(User.class))).willReturn(REFRESH_TOKEN);
            given(jwtService.getAccessTokenExpiration()).willReturn(EXPIRATION);
            given(jwtService.getRefreshTokenExpiration()).willReturn(86400000L);
            given(refreshTokenRepository.save(any(RefreshToken.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            AuthenticationResponseDto result = authenticationService.signUp(createUserDto, IP_ADDRESS, USER_AGENT);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(result.expiresIn()).isEqualTo(EXPIRATION);

            // ArgumentCaptor - verify user was saved with correct data
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getUsername()).isEqualTo("newuser");
            assertThat(savedUser.getEmail()).isEqualTo("newuser@example.com");
            assertThat(savedUser.getPassword()).isEqualTo("encodedPassword");
            assertThat(savedUser.getEnabled()).isTrue();
            assertThat(savedUser.getIsLocked()).isFalse();
            assertThat(savedUser.getRoles()).contains(userRole);

            // Verification
            verify(passwordEncoder).encode("password123");
            verify(jwtService).generateToken(any(User.class));
            verify(jwtService).generateRefreshToken(any(User.class));
        }

        @Test
        void shouldThrowExceptionWhenEmailExists() {
            // GIVEN
            CreateUserDto createUserDto = new CreateUserDto("newuser", "existing@example.com", "password123");
            given(userRepository.existsByEmail("existing@example.com")).willReturn(true);

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> authenticationService.signUp(createUserDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(DuplicateResourceException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("email");

            // Verification: no user should be saved
            verify(userRepository, never()).save(any());
            verify(jwtService, never()).generateToken(any());
        }

        @Test
        void shouldThrowExceptionWhenUsernameExists() {
            // GIVEN
            CreateUserDto createUserDto = new CreateUserDto("existinguser", "new@example.com", "password123");
            given(userRepository.existsByEmail("new@example.com")).willReturn(false);
            given(userRepository.existsByUsername("existinguser")).willReturn(true);

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.signUp(createUserDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(DuplicateResourceException.class)
                    .hasMessageContaining("User")
                    .hasMessageContaining("username");

            verify(userRepository, never()).save(any());
        }

        @Test
        void shouldThrowExceptionWhenUserRoleNotFound() {
            // GIVEN
            CreateUserDto createUserDto = new CreateUserDto("newuser", "new@example.com", "password123");
            given(userRepository.existsByEmail("new@example.com")).willReturn(false);
            given(userRepository.existsByUsername("newuser")).willReturn(false);
            given(roleRepository.findByName("USER")).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.signUp(createUserDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Role");

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    class AuthenticateTests {

        @Test
        void shouldAuthenticateSuccessfully() {
            // GIVEN
            LoginUserDto loginDto = new LoginUserDto("testuser", "password123");

            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(testUser));
            given(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .willReturn(new UsernamePasswordAuthenticationToken(testUser, null));
            given(userRepository.save(any(User.class))).willReturn(testUser);
            given(jwtService.generateToken(testUser)).willReturn(ACCESS_TOKEN);
            given(jwtService.generateRefreshToken(testUser)).willReturn(REFRESH_TOKEN);
            given(jwtService.getAccessTokenExpiration()).willReturn(EXPIRATION);
            given(jwtService.getRefreshTokenExpiration()).willReturn(86400000L);
            given(refreshTokenRepository.save(any(RefreshToken.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            AuthenticationResponseDto result = authenticationService.authenticate(loginDto, IP_ADDRESS, USER_AGENT);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.accessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);

            // Verification - AuthenticationManager was called with correct credentials
            verify(authenticationManager).authenticate(authTokenCaptor.capture());
            UsernamePasswordAuthenticationToken capturedToken = authTokenCaptor.getValue();
            assertThat(capturedToken.getPrincipal()).isEqualTo("testuser");
            assertThat(capturedToken.getCredentials()).isEqualTo("password123");

            // Verify user's last login was updated
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getFailedLoginAttempts()).isZero();
        }

        @Test
        void shouldThrowExceptionWhenUserNotFound() {
            // GIVEN
            LoginUserDto loginDto = new LoginUserDto("nonexistent", "password123");
            given(userRepository.findByUsernameWithRoles("nonexistent")).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.authenticate(loginDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(BadCredentialsException.class);

            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        void shouldThrowExceptionWhenAccountLocked() {
            // GIVEN
            User lockedUser = User.builder()
                    .id(1L)
                    .username("lockeduser")
                    .email("locked@example.com")
                    .password("encodedPassword")
                    .enabled(true)
                    .isLocked(true)
                    .failedLoginAttempts(5)
                    .roles(Set.of(userRole))
                    .build();

            LoginUserDto loginDto = new LoginUserDto("lockeduser", "password123");
            given(userRepository.findByUsernameWithRoles("lockeduser")).willReturn(Optional.of(lockedUser));

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.authenticate(loginDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(AccountLockedException.class);

            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        void shouldThrowExceptionWhenAccountDisabled() {
            // GIVEN
            User disabledUser = User.builder()
                    .id(1L)
                    .username("disableduser")
                    .email("disabled@example.com")
                    .password("encodedPassword")
                    .enabled(false)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .roles(Set.of(userRole))
                    .build();

            LoginUserDto loginDto = new LoginUserDto("disableduser", "password123");
            given(userRepository.findByUsernameWithRoles("disableduser")).willReturn(Optional.of(disabledUser));

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.authenticate(loginDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(AccountDisabledException.class);

            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        void shouldIncrementFailedAttemptsOnWrongPassword() {
            // GIVEN
            User userWithAttempts = User.builder()
                    .id(1L)
                    .username("testuser")
                    .email("test@example.com")
                    .password("encodedPassword")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .roles(Set.of(userRole))
                    .build();

            LoginUserDto loginDto = new LoginUserDto("testuser", "wrongpassword");
            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(userWithAttempts));
            given(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .willThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.authenticate(loginDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(BadCredentialsException.class);

            // ArgumentCaptor - verify failed attempts were incremented
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(1);
        }

        @Test
        void shouldLockAccountAfterFiveFailedAttempts() {
            // GIVEN
            User userNearLockout = User.builder()
                    .id(1L)
                    .username("testuser")
                    .email("test@example.com")
                    .password("encodedPassword")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(4)
                    .roles(Set.of(userRole))
                    .build();

            LoginUserDto loginDto = new LoginUserDto("testuser", "wrongpassword");
            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(userNearLockout));
            given(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .willThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));
            given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.authenticate(loginDto, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(BadCredentialsException.class);

            // ArgumentCaptor - verify account was locked
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(5);
            assertThat(savedUser.getIsLocked()).isTrue();
        }
    }

    @Nested
    class RefreshTokenTests {

        @Test
        @DisplayName("GIVEN valid refresh token WHEN refreshToken is called THEN returns new tokens")
        void shouldRefreshTokenSuccessfully() {
            // GIVEN
            String oldRefreshToken = "old.refresh.token";
            String newAccessToken = "new.access.token";
            String newRefreshToken = "new.refresh.token";

            RefreshToken storedToken = RefreshToken.builder()
                    .id(1L)
                    .user(testUser)
                    .tokenHash("hashedToken")
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .isRevoked(false)
                    .build();

            given(jwtService.extractUsername(oldRefreshToken)).willReturn("testuser");
            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(testUser));
            given(jwtService.isTokenValid(oldRefreshToken, testUser)).willReturn(true);
            given(refreshTokenRepository.findByTokenHash(anyString())).willReturn(Optional.of(storedToken));
            given(jwtService.generateToken(testUser)).willReturn(newAccessToken);
            given(jwtService.generateRefreshToken(testUser)).willReturn(newRefreshToken);
            given(jwtService.getAccessTokenExpiration()).willReturn(EXPIRATION);
            given(jwtService.getRefreshTokenExpiration()).willReturn(86400000L);
            given(refreshTokenRepository.save(any(RefreshToken.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            AuthenticationResponseDto result = authenticationService.refreshToken(oldRefreshToken, IP_ADDRESS, USER_AGENT);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.accessToken()).isEqualTo(newAccessToken);
            assertThat(result.refreshToken()).isEqualTo(newRefreshToken);

            // Verification
            verify(jwtService).isTokenValid(oldRefreshToken, testUser);
            verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
        }

        @Test
        void shouldThrowExceptionWhenTokenInvalid() {
            // GIVEN
            String invalidToken = "invalid.refresh.token";

            given(jwtService.extractUsername(invalidToken)).willReturn("testuser");
            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(testUser));
            given(jwtService.isTokenValid(invalidToken, testUser)).willReturn(false);

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.refreshToken(invalidToken, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(InvalidTokenException.class);

            verify(refreshTokenRepository, never()).findByTokenHash(anyString());
        }

        @Test
        void shouldThrowExceptionWhenTokenNotFoundInRepository() {
            // GIVEN
            String refreshToken = "not.found.token";

            given(jwtService.extractUsername(refreshToken)).willReturn("testuser");
            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(testUser));
            given(jwtService.isTokenValid(refreshToken, testUser)).willReturn(true);
            given(refreshTokenRepository.findByTokenHash(anyString())).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.refreshToken(refreshToken, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("not found");
        }

        @Test
        void shouldRevokeAllTokensOnTokenReuse() {
            // GIVEN
            String reusedToken = "reused.refresh.token";

            RefreshToken storedToken = RefreshToken.builder()
                    .id(1L)
                    .user(testUser)
                    .tokenHash("hashedToken")
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .isRevoked(false)
                    .replaceBy(RefreshToken.builder().id(2L).build()) // Token has been replaced
                    .build();

            given(jwtService.extractUsername(reusedToken)).willReturn("testuser");
            given(userRepository.findByUsernameWithRoles("testuser")).willReturn(Optional.of(testUser));
            given(jwtService.isTokenValid(reusedToken, testUser)).willReturn(true);
            given(refreshTokenRepository.findByTokenHash(anyString())).willReturn(Optional.of(storedToken));

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.refreshToken(reusedToken, IP_ADDRESS, USER_AGENT))
                    .isInstanceOf(TokenRevokedException.class)
                    .hasMessageContaining("reuse detected");

            // Verification - all user tokens should be revoked
            verify(refreshTokenRepository).revokeAllUserTokens(testUser);
        }
    }

    @Nested
    class LogoutTests {

        @Test
        void shouldRevokeTokenOnLogout() {
            // GIVEN
            String refreshToken = "valid.refresh.token";
            RefreshToken storedToken = RefreshToken.builder()
                    .id(1L)
                    .user(testUser)
                    .tokenHash("hashedToken")
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .isRevoked(false)
                    .build();

            given(refreshTokenRepository.findByTokenHash(anyString())).willReturn(Optional.of(storedToken));
            given(refreshTokenRepository.save(any(RefreshToken.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            authenticationService.logout(refreshToken);

            // THEN - ArgumentCaptor to verify token was revoked
            verify(refreshTokenRepository).save(refreshTokenCaptor.capture());
            RefreshToken savedToken = refreshTokenCaptor.getValue();
            assertThat(savedToken.getIsRevoked()).isTrue();
        }

        @Test
        void shouldCompleteSilentlyWhenTokenNotFound() {
            // GIVEN
            String nonExistentToken = "nonexistent.token";
            given(refreshTokenRepository.findByTokenHash(anyString())).willReturn(Optional.empty());

            // WHEN
            authenticationService.logout(nonExistentToken);

            // THEN - No exception, no save called
            verify(refreshTokenRepository, never()).save(any());
        }
    }

    @Nested
    class LogoutAllDevicesTests {

        @Test
        void shouldRevokeAllUserTokens() {
            // GIVEN
            String username = "testuser";
            given(userRepository.findByUsername(username)).willReturn(Optional.of(testUser));

            // WHEN
            authenticationService.logoutAllDevices(username);

            // THEN
            verify(refreshTokenRepository).revokeAllUserTokens(testUser);
        }

        @Test
        void shouldThrowExceptionWhenUserNotFoundForLogoutAll() {
            // GIVEN
            String nonExistentUsername = "nonexistent";
            given(userRepository.findByUsername(nonExistentUsername)).willReturn(Optional.empty());

            // WHEN/THEN
            assertThatThrownBy(() -> authenticationService.logoutAllDevices(nonExistentUsername))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User");

            verify(refreshTokenRepository, never()).revokeAllUserTokens(any());
        }
    }
}
