package identityaccessmanagement.example.Identity.Access.Management.repository;

import identityaccessmanagement.example.Identity.Access.Management.model.RefreshToken;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest
@DisplayName("RefreshTokenRepository Tests")
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EntityManager entityManager;

    private User testUser;
    private RefreshToken activeToken;
    private RefreshToken expiredToken;

    @BeforeEach
    void setUp() {
        // Clear previous test data
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Create and persist user
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .build();
        testUser = userRepository.save(testUser);

        // Create active token
        activeToken = RefreshToken.builder()
                .user(testUser)
                .tokenHash("activeTokenHash123")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .isRevoked(false)
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .build();
        activeToken = refreshTokenRepository.save(activeToken);

        // Create expired token
        expiredToken = RefreshToken.builder()
                .user(testUser)
                .tokenHash("expiredTokenHash456")
                .expiresAt(LocalDateTime.now().minusDays(1))
                .isRevoked(false)
                .ipAddress("192.168.1.2")
                .userAgent("Chrome/100")
                .build();
        expiredToken = refreshTokenRepository.save(expiredToken);
    }

    @Nested
    @DisplayName("findByTokenHash Tests")
    class FindByTokenHashTests {

        @Test
        @DisplayName("GIVEN token exists WHEN findByTokenHash is called THEN returns token with user loaded")
        void shouldFindTokenByHash() {
            // GIVEN - token already persisted in setUp

            // WHEN
            Optional<RefreshToken> result = refreshTokenRepository.findByTokenHash("activeTokenHash123");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getTokenHash()).isEqualTo("activeTokenHash123");
            assertThat(result.get().getUser()).isNotNull();
            assertThat(result.get().getUser().getUsername()).isEqualTo("testuser");
        }

        @Test
        @DisplayName("GIVEN token doesn't exist WHEN findByTokenHash is called THEN returns empty")
        void shouldReturnEmptyWhenTokenNotFound() {
            // GIVEN - no token with this hash

            // WHEN
            Optional<RefreshToken> result = refreshTokenRepository.findByTokenHash("nonexistentHash");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("GIVEN expired token WHEN findByTokenHash is called THEN still returns the token")
        void shouldFindExpiredToken() {
            // GIVEN - expired token already persisted

            // WHEN
            Optional<RefreshToken> result = refreshTokenRepository.findByTokenHash("expiredTokenHash456");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().isExpired()).isTrue();
        }

        @Test
        @DisplayName("GIVEN token with user WHEN findByTokenHash is called THEN user is eagerly fetched")
        void shouldEagerlyFetchUser() {
            // GIVEN - token with user already persisted

            // WHEN
            Optional<RefreshToken> result = refreshTokenRepository.findByTokenHash("activeTokenHash123");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getUser().getEmail()).isEqualTo("test@example.com");
        }
    }

    @Nested
    @DisplayName("revokeAllUserTokens Tests")
    class RevokeAllUserTokensTests {

        @Test
        @DisplayName("GIVEN user has active tokens WHEN revokeAllUserTokens is called THEN all tokens are revoked")
        void shouldRevokeAllUserTokens() {
            // GIVEN - create another active token for the user
            RefreshToken anotherToken = RefreshToken.builder()
                    .user(testUser)
                    .tokenHash("anotherActiveHash789")
                    .expiresAt(LocalDateTime.now().plusDays(7))
                    .isRevoked(false)
                    .build();
            refreshTokenRepository.save(anotherToken);

            // WHEN
            refreshTokenRepository.revokeAllUserTokens(testUser);
            // Clear persistence context to see the database changes from @Modifying query
            entityManager.flush();
            entityManager.clear();

            // THEN
            Optional<RefreshToken> token1 = refreshTokenRepository.findByTokenHash("activeTokenHash123");
            Optional<RefreshToken> token2 = refreshTokenRepository.findByTokenHash("anotherActiveHash789");

            assertThat(token1).isPresent();
            assertThat(token1.get().getIsRevoked()).isTrue();

            assertThat(token2).isPresent();
            assertThat(token2.get().getIsRevoked()).isTrue();
        }

        @Test
        @DisplayName("GIVEN user has no active tokens WHEN revokeAllUserTokens is called THEN completes without error")
        void shouldHandleNoActiveTokens() {
            // GIVEN - create user with no tokens
            User userWithNoTokens = User.builder()
                    .username("notokens")
                    .email("notokens@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();
            userWithNoTokens = userRepository.save(userWithNoTokens);

            // WHEN - should not throw
            refreshTokenRepository.revokeAllUserTokens(userWithNoTokens);

            // THEN - no exception means success
            assertThat(true).isTrue();
        }

        @Test
        @DisplayName("GIVEN user has already revoked tokens WHEN revokeAllUserTokens is called THEN already revoked tokens stay revoked")
        void shouldNotAffectAlreadyRevokedTokens() {
            // GIVEN - create a revoked token
            RefreshToken revokedToken = RefreshToken.builder()
                    .user(testUser)
                    .tokenHash("alreadyRevokedHash")
                    .expiresAt(LocalDateTime.now().plusDays(7))
                    .isRevoked(true)
                    .revokedAt(LocalDateTime.now().minusHours(1))
                    .revocationReason("Previous revocation")
                    .build();
            refreshTokenRepository.save(revokedToken);

            // WHEN
            refreshTokenRepository.revokeAllUserTokens(testUser);

            // THEN - token should still be revoked
            Optional<RefreshToken> result = refreshTokenRepository.findByTokenHash("alreadyRevokedHash");
            assertThat(result).isPresent();
            assertThat(result.get().getIsRevoked()).isTrue();
        }
    }

    @Nested
    @DisplayName("deleteByExpiresAtBefore Tests")
    class DeleteByExpiresAtBeforeTests {

        @Test
        @DisplayName("GIVEN expired tokens exist WHEN deleteByExpiresAtBefore is called THEN expired tokens are deleted")
        void shouldDeleteExpiredTokens() {
            // GIVEN - expired token already persisted in setUp
            LocalDateTime cutoffDate = LocalDateTime.now();

            // WHEN
            refreshTokenRepository.deleteByExpiresAtBefore(cutoffDate);

            // THEN
            Optional<RefreshToken> expiredResult = refreshTokenRepository.findByTokenHash("expiredTokenHash456");
            Optional<RefreshToken> activeResult = refreshTokenRepository.findByTokenHash("activeTokenHash123");

            assertThat(expiredResult).isEmpty(); // Deleted
            assertThat(activeResult).isPresent(); // Still exists
        }

        @Test
        @DisplayName("GIVEN no expired tokens WHEN deleteByExpiresAtBefore is called THEN no tokens are deleted")
        void shouldNotDeleteNonExpiredTokens() {
            // GIVEN - only delete tokens expired before a past date
            LocalDateTime pastCutoff = LocalDateTime.now().minusYears(1);

            // WHEN
            refreshTokenRepository.deleteByExpiresAtBefore(pastCutoff);

            // THEN - both tokens should still exist
            assertThat(refreshTokenRepository.findByTokenHash("activeTokenHash123")).isPresent();
            assertThat(refreshTokenRepository.findByTokenHash("expiredTokenHash456")).isPresent();
        }
    }

    @Nested
    @DisplayName("CRUD Operations Tests")
    class CrudOperationsTests {

        @Test
        @DisplayName("GIVEN new token WHEN save is called THEN token is persisted")
        void shouldSaveNewToken() {
            // GIVEN
            RefreshToken newToken = RefreshToken.builder()
                    .user(testUser)
                    .tokenHash("newTokenHash999")
                    .expiresAt(LocalDateTime.now().plusDays(30))
                    .isRevoked(false)
                    .ipAddress("10.0.0.1")
                    .build();

            // WHEN
            RefreshToken savedToken = refreshTokenRepository.save(newToken);

            // THEN
            assertThat(savedToken.getId()).isNotNull();
            assertThat(savedToken.getTokenHash()).isEqualTo("newTokenHash999");
        }

        @Test
        @DisplayName("GIVEN token WHEN revoke is called THEN token is marked as revoked")
        void shouldRevokeToken() {
            // GIVEN
            Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash("activeTokenHash123");
            assertThat(tokenOpt).isPresent();
            RefreshToken token = tokenOpt.get();

            // WHEN
            token.revoke("User requested logout");
            refreshTokenRepository.save(token);

            // THEN
            Optional<RefreshToken> revokedToken = refreshTokenRepository.findByTokenHash("activeTokenHash123");
            assertThat(revokedToken).isPresent();
            assertThat(revokedToken.get().getIsRevoked()).isTrue();
            assertThat(revokedToken.get().getRevocationReason()).isEqualTo("User requested logout");
        }
    }
}
