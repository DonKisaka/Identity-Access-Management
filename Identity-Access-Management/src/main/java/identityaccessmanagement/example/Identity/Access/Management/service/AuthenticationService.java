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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Set;

@Service
public class AuthenticationService {
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthenticationService(JwtService jwtService, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, RefreshTokenRepository refreshTokenRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    @Transactional
    public AuthenticationResponseDto signUp(CreateUserDto dto, String ipAddress, String userAgent) {
        if (userRepository.existsByEmail(dto.email())) {
            throw new DuplicateResourceException("User", "email", dto.email());
        }

        if (userRepository.existsByUsername(dto.username())) {
            throw new DuplicateResourceException("User", "username", dto.username());
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new ResourceNotFoundException("Role", "name", "USER"));

        User user = User.builder()
                .username(dto.username())
                .email(dto.email())
                .password(passwordEncoder.encode(dto.password()))
                .roles(Set.of(userRole))
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .build();

        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        saveRefreshToken(user, refreshToken, ipAddress, userAgent);

        return new AuthenticationResponseDto(accessToken, refreshToken, jwtService.getAccessTokenExpiration());
    }

    @Transactional
    public AuthenticationResponseDto authenticate(LoginUserDto dto, String ipAddress, String userAgent) {
        User user = userRepository.findByUsernameWithRoles(dto.username())
                .orElseThrow(() -> new BadCredentialsException());

        if (user.getIsLocked()) {
            throw new AccountLockedException();
        }

        if (!user.isEnabled()) {
            throw new AccountDisabledException();
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            dto.username(),
                            dto.password()
                    )
            );
        } catch (Exception e) {
            handleFailedLogin(user);
            throw new BadCredentialsException();
        }

        user.resetFailedAttempts();
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        saveRefreshToken(user, refreshToken, ipAddress, userAgent);

        return new AuthenticationResponseDto(accessToken, refreshToken, jwtService.getAccessTokenExpiration());
    }

    @Transactional
    public AuthenticationResponseDto refreshToken(String refreshToken, String ipAddress, String userAgent) {
        String username = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByUsernameWithRoles(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        if(!jwtService.isTokenValid(refreshToken, user)) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        String tokenHash = hashToken(refreshToken);
        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (storedToken.getReplaceBy() != null) {
            refreshTokenRepository.revokeAllUserTokens(user);
            throw new TokenRevokedException("Refresh token reuse detected - all tokens revoked for security");
        }

        if (!storedToken.isValid()) {
            throw new InvalidTokenException("Refresh token has expired or been revoked");
        }

        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        RefreshToken newStoredToken = saveRefreshToken(user, newRefreshToken, ipAddress, userAgent);
        storedToken.rotate(newStoredToken);
        refreshTokenRepository.save(storedToken);


        return new AuthenticationResponseDto(newAccessToken, newRefreshToken, jwtService.getAccessTokenExpiration());
    }

    private void handleFailedLogin(User user) {
        user.incrementFailedAttempts();

        if (user.getFailedLoginAttempts() >= 5) {
            user.lock();
        }

        userRepository.save(user);
    }

    @Transactional
    public void logout(String refreshToken) {
        String tokenHash = hashToken(refreshToken);
        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElse(null);

        if (storedToken != null) {
            storedToken.revoke("User logout");
            refreshTokenRepository.save(storedToken);
        }
    }

    @Transactional
    public void logoutAllDevices(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        refreshTokenRepository.revokeAllUserTokens(user);
    }

    private RefreshToken saveRefreshToken(User user, String refreshToken, String ipAddress, String userAgent) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .tokenHash(hashToken(refreshToken))
                .expiresAt(LocalDateTime.now().plusSeconds(jwtService.getRefreshTokenExpiration() / 1000))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .isRevoked(false)
                .build();

        return refreshTokenRepository.save(token);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


}
