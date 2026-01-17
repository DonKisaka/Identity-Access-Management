package identityaccessmanagement.example.Identity.Access.Management.repository;

import identityaccessmanagement.example.Identity.Access.Management.model.PasswordResetToken;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest
class PasswordResetTokenRepositoryTest {

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EntityManager entityManager;

    private User testUser;
    private PasswordResetToken validToken;
    private PasswordResetToken expiredToken;
    private PasswordResetToken usedToken;

    @BeforeEach
    void setUp() {
        // Clear previous test data
        passwordResetTokenRepository.deleteAll();
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

        // Create valid (unused, not expired) token
        validToken = PasswordResetToken.builder()
                .user(testUser)
                .tokenHash("validTokenHash123")
                .expiresAt(LocalDateTime.now().plusHours(1))
                .isUsed(false)
                .build();
        validToken = passwordResetTokenRepository.save(validToken);

        // Create expired token
        expiredToken = PasswordResetToken.builder()
                .user(testUser)
                .tokenHash("expiredTokenHash456")
                .expiresAt(LocalDateTime.now().minusHours(1))
                .isUsed(false)
                .build();
        expiredToken = passwordResetTokenRepository.save(expiredToken);

        // Create used token
        usedToken = PasswordResetToken.builder()
                .user(testUser)
                .tokenHash("usedTokenHash789")
                .expiresAt(LocalDateTime.now().plusHours(1))
                .isUsed(true)
                .usedAt(LocalDateTime.now().minusMinutes(30))
                .build();
        usedToken = passwordResetTokenRepository.save(usedToken);
    }

    @Nested
    class FindByTokenHashTests {

        @Test
        void shouldFindTokenByHash() {
            // GIVEN - token already persisted in setUp

            // WHEN
            Optional<PasswordResetToken> result = passwordResetTokenRepository.findByTokenHash("validTokenHash123");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getTokenHash()).isEqualTo("validTokenHash123");
            assertThat(result.get().getIsUsed()).isFalse();
        }

        @Test
        void shouldReturnEmptyWhenTokenNotFound() {
            // GIVEN - no token with this hash

            // WHEN
            Optional<PasswordResetToken> result = passwordResetTokenRepository.findByTokenHash("nonexistentHash");

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        void shouldFindExpiredToken() {
            // GIVEN - expired token already persisted

            // WHEN
            Optional<PasswordResetToken> result = passwordResetTokenRepository.findByTokenHash("expiredTokenHash456");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().isExpired()).isTrue();
        }

        @Test
        void shouldFindUsedToken() {
            // GIVEN - used token already persisted

            // WHEN
            Optional<PasswordResetToken> result = passwordResetTokenRepository.findByTokenHash("usedTokenHash789");

            // THEN
            assertThat(result).isPresent();
            assertThat(result.get().getIsUsed()).isTrue();
        }
    }

    @Nested
    class FindValidTokensForUserTests {

        @Test
        void shouldFindValidTokensForUser() {
            // GIVEN
            LocalDateTime now = LocalDateTime.now();

            // WHEN
            List<PasswordResetToken> result = passwordResetTokenRepository
                    .findByUserAndIsUsedFalseAndExpiresAtAfter(testUser, now);

            // THEN
            assertThat(result).hasSize(1);
            assertThat(result.get(0).getTokenHash()).isEqualTo("validTokenHash123");
        }

        @Test
        void shouldReturnEmptyWhenNoValidTokens() {
            // GIVEN - create user with only expired/used tokens
            User anotherUser = User.builder()
                    .username("anotheruser")
                    .email("another@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();
            anotherUser = userRepository.save(anotherUser);

            // WHEN
            List<PasswordResetToken> result = passwordResetTokenRepository
                    .findByUserAndIsUsedFalseAndExpiresAtAfter(anotherUser, LocalDateTime.now());

            // THEN
            assertThat(result).isEmpty();
        }

        @Test
        void shouldFindMultipleValidTokens() {
            // GIVEN - create another valid token
            PasswordResetToken anotherValidToken = PasswordResetToken.builder()
                    .user(testUser)
                    .tokenHash("anotherValidHash")
                    .expiresAt(LocalDateTime.now().plusHours(2))
                    .isUsed(false)
                    .build();
            passwordResetTokenRepository.save(anotherValidToken);

            // WHEN
            List<PasswordResetToken> result = passwordResetTokenRepository
                    .findByUserAndIsUsedFalseAndExpiresAtAfter(testUser, LocalDateTime.now());

            // THEN
            assertThat(result).hasSize(2);
        }
    }

    @Nested
    class InvalidateAllUserTokensTests {

        @Test
        void shouldInvalidateAllUserTokens() {
            // GIVEN - tokens already persisted

            // WHEN
            passwordResetTokenRepository.invalidateAllUserTokens(testUser);
            // Clear persistence context to see the database changes from @Modifying query
            entityManager.flush();
            entityManager.clear();

            // THEN
            Optional<PasswordResetToken> token1 = passwordResetTokenRepository.findByTokenHash("validTokenHash123");
            Optional<PasswordResetToken> token2 = passwordResetTokenRepository.findByTokenHash("expiredTokenHash456");

            assertThat(token1).isPresent();
            assertThat(token1.get().getIsUsed()).isTrue();

            assertThat(token2).isPresent();
            assertThat(token2.get().getIsUsed()).isTrue();
        }

        @Test
        void shouldHandleNoUnusedTokens() {
            // GIVEN - create user with only used tokens
            User userWithUsedTokens = User.builder()
                    .username("usedtokens")
                    .email("usedtokens@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();
            userWithUsedTokens = userRepository.save(userWithUsedTokens);

            PasswordResetToken alreadyUsed = PasswordResetToken.builder()
                    .user(userWithUsedTokens)
                    .tokenHash("alreadyUsedHash")
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .isUsed(true)
                    .build();
            passwordResetTokenRepository.save(alreadyUsed);

            // WHEN - should not throw
            passwordResetTokenRepository.invalidateAllUserTokens(userWithUsedTokens);

            // THEN - no exception means success
            assertThat(true).isTrue();
        }
    }

    @Nested
    class DeleteByExpiresAtBeforeTests {

        @Test
        void shouldDeleteExpiredTokens() {
            // GIVEN
            LocalDateTime cutoffDate = LocalDateTime.now();

            // WHEN
            passwordResetTokenRepository.deleteByExpiresAtBefore(cutoffDate);

            // THEN
            Optional<PasswordResetToken> expiredResult = passwordResetTokenRepository.findByTokenHash("expiredTokenHash456");
            Optional<PasswordResetToken> validResult = passwordResetTokenRepository.findByTokenHash("validTokenHash123");

            assertThat(expiredResult).isEmpty(); // Deleted
            assertThat(validResult).isPresent(); // Still exists
        }

        @Test
        void shouldNotDeleteValidTokens() {
            // GIVEN
            LocalDateTime pastCutoff = LocalDateTime.now().minusYears(1);

            // WHEN
            passwordResetTokenRepository.deleteByExpiresAtBefore(pastCutoff);

            // THEN - all tokens should still exist
            assertThat(passwordResetTokenRepository.findByTokenHash("validTokenHash123")).isPresent();
            assertThat(passwordResetTokenRepository.findByTokenHash("expiredTokenHash456")).isPresent();
            assertThat(passwordResetTokenRepository.findByTokenHash("usedTokenHash789")).isPresent();
        }
    }

    @Nested
    class TokenLifecycleTests {

        @Test
        void shouldMarkTokenAsUsed() {
            // GIVEN
            Optional<PasswordResetToken> tokenOpt = passwordResetTokenRepository.findByTokenHash("validTokenHash123");
            assertThat(tokenOpt).isPresent();
            PasswordResetToken token = tokenOpt.get();
            assertThat(token.isValid()).isTrue();

            // WHEN
            token.markAsUsed();
            passwordResetTokenRepository.save(token);

            // THEN
            Optional<PasswordResetToken> usedTokenOpt = passwordResetTokenRepository.findByTokenHash("validTokenHash123");
            assertThat(usedTokenOpt).isPresent();
            assertThat(usedTokenOpt.get().getIsUsed()).isTrue();
            assertThat(usedTokenOpt.get().getUsedAt()).isNotNull();
            assertThat(usedTokenOpt.get().isValid()).isFalse();
        }

        @Test
        void shouldSetCreatedAtOnPersist() {
            // GIVEN
            PasswordResetToken newToken = PasswordResetToken.builder()
                    .user(testUser)
                    .tokenHash("newTokenHash")
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .isUsed(false)
                    .build();

            // WHEN
            passwordResetTokenRepository.save(newToken);

            // THEN
            Optional<PasswordResetToken> savedToken = passwordResetTokenRepository.findByTokenHash("newTokenHash");
            assertThat(savedToken).isPresent();
            assertThat(savedToken.get().getCreatedAt()).isNotNull();
        }
    }
}
