package identityaccessmanagement.example.Identity.Access.Management.repository;

import identityaccessmanagement.example.Identity.Access.Management.model.AuditLog;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest
class AuditLogRepositoryTest {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private UserRepository userRepository;

    private User testUser;
    private User anotherUser;
    private AuditLog loginLog;
    private AuditLog logoutLog;
    private AuditLog failedLoginLog;

    @BeforeEach
    void setUp() {
        // Clear previous test data
        auditLogRepository.deleteAll();
        userRepository.deleteAll();

        // Create and persist users
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .build();
        testUser = userRepository.save(testUser);

        anotherUser = User.builder()
                .username("anotheruser")
                .email("another@example.com")
                .password("encodedPassword")
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .build();
        anotherUser = userRepository.save(anotherUser);

        // Create audit logs for testUser
        loginLog = AuditLog.builder()
                .user(testUser)
                .action("LOGIN")
                .status("SUCCESS")
                .details("User logged in successfully")
                .ipAddress("192.168.1.1")
                .build();
        loginLog = auditLogRepository.save(loginLog);

        logoutLog = AuditLog.builder()
                .user(testUser)
                .action("LOGOUT")
                .status("SUCCESS")
                .details("User logged out")
                .ipAddress("192.168.1.1")
                .build();
        logoutLog = auditLogRepository.save(logoutLog);

        failedLoginLog = AuditLog.builder()
                .user(testUser)
                .action("LOGIN")
                .status("FAILURE")
                .details("Invalid password")
                .ipAddress("192.168.1.100")
                .build();
        failedLoginLog = auditLogRepository.save(failedLoginLog);

        // Create audit log for anotherUser
        AuditLog anotherUserLog = AuditLog.builder()
                .user(anotherUser)
                .action("LOGIN")
                .status("SUCCESS")
                .details("Another user logged in")
                .ipAddress("10.0.0.1")
                .build();
        auditLogRepository.save(anotherUserLog);
    }

    @Nested
    class FindByUserIdTests {

        @Test
        void shouldFindLogsByUserId() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByUserId(testUser.getId(), pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(3);
            assertThat(result.getContent()).allMatch(log -> log.getUser().getId().equals(testUser.getId()));
        }

        @Test
        void shouldReturnEmptyPageWhenNoLogs() {
            // GIVEN - create user with no logs
            User userWithNoLogs = User.builder()
                    .username("nologs")
                    .email("nologs@example.com")
                    .password("password")
                    .enabled(true)
                    .isLocked(false)
                    .failedLoginAttempts(0)
                    .build();
            userWithNoLogs = userRepository.save(userWithNoLogs);

            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByUserId(userWithNoLogs.getId(), pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
        }

        @Test
        void shouldRespectPagination() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 2);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByUserId(testUser.getId(), pageable);

            // THEN
            assertThat(result.getContent()).hasSize(2);
            assertThat(result.getTotalElements()).isEqualTo(3);
            assertThat(result.getTotalPages()).isEqualTo(2);
        }

        @Test
        void shouldReturnCorrectPage() {
            // GIVEN
            Pageable pageable = PageRequest.of(1, 2);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByUserId(testUser.getId(), pageable);

            // THEN
            assertThat(result.getContent()).hasSize(1); // 3 total, page 2 has 1
            assertThat(result.getNumber()).isEqualTo(1);
        }
    }

    @Nested
    class FindByActionAndStatusTests {

        @Test
        void shouldFindLogsByActionAndStatus() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByActionAndStatus("LOGIN", "SUCCESS", pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(2); // testUser and anotherUser login success
            assertThat(result.getContent()).allMatch(log ->
                    log.getAction().equals("LOGIN") && log.getStatus().equals("SUCCESS"));
        }

        @Test
        void shouldFindFailedLogs() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByActionAndStatus("LOGIN", "FAILURE", pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(1);
            assertThat(result.getContent().get(0).getDetails()).contains("Invalid password");
        }

        @Test
        void shouldReturnEmptyWhenNoMatch() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByActionAndStatus("DELETE", "SUCCESS", pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
        }

        @Test
        void shouldFindLogoutLogs() {
            // GIVEN
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByActionAndStatus("LOGOUT", "SUCCESS", pageable);

            // THEN
            assertThat(result.getContent()).hasSize(1);
            assertThat(result.getContent().get(0).getAction()).isEqualTo("LOGOUT");
        }
    }

    @Nested
    class FindByCreatedAtBetweenTests {

        @Test
        void shouldFindLogsInDateRange() {
            // GIVEN - All logs are created with @PrePersist setting createdAt to now()
            LocalDateTime start = LocalDateTime.now().minusMinutes(5);
            LocalDateTime end = LocalDateTime.now().plusMinutes(5);
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByCreatedAtBetween(start, end, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(4); // All logs created around now()
        }

        @Test
        void shouldFindLogsInCurrentTimeRange() {
            // GIVEN - All logs have createdAt set to approximately now() by @PrePersist
            LocalDateTime start = LocalDateTime.now().minusHours(1);
            LocalDateTime end = LocalDateTime.now().plusHours(1);
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByCreatedAtBetween(start, end, pageable);

            // THEN
            assertThat(result.getContent()).hasSize(4); // All logs should be found
        }

        @Test
        void shouldReturnEmptyWhenNoLogsInRange() {
            // GIVEN - date range in the future
            LocalDateTime start = LocalDateTime.now().plusDays(10);
            LocalDateTime end = LocalDateTime.now().plusDays(20);
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByCreatedAtBetween(start, end, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
        }

        @Test
        void shouldReturnEmptyWhenDateRangeInPast() {
            // GIVEN - date range in the past (logs are created at now() by @PrePersist)
            LocalDateTime start = LocalDateTime.now().minusDays(10);
            LocalDateTime end = LocalDateTime.now().minusDays(5);
            Pageable pageable = PageRequest.of(0, 10);

            // WHEN
            Page<AuditLog> result = auditLogRepository.findByCreatedAtBetween(start, end, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
        }
    }



    @Nested
    class AuditLogMetadataTests {

        @Test
        void shouldPreserveAllFields() {
            // GIVEN
            LocalDateTime timestamp = LocalDateTime.now();

            AuditLog detailedLog = AuditLog.builder()
                    .user(testUser)
                    .action("ROLE_ASSIGNMENT")
                    .status("SUCCESS")
                    .severity("INFO")
                    .resource("roles")
                    .ipAddress("10.0.0.50")
                    .userAgent("CustomAgent/1.0")
                    .details("Assigned ADMIN role to user")
                    .createdAt(timestamp)
                    .build();

            // WHEN
            AuditLog saved = auditLogRepository.save(detailedLog);

            // THEN
            AuditLog found = auditLogRepository.findById(saved.getId()).orElseThrow();
            assertThat(found.getAction()).isEqualTo("ROLE_ASSIGNMENT");
            assertThat(found.getStatus()).isEqualTo("SUCCESS");
            assertThat(found.getSeverity()).isEqualTo("INFO");
            assertThat(found.getResource()).isEqualTo("roles");
            assertThat(found.getIpAddress()).isEqualTo("10.0.0.50");
            assertThat(found.getUserAgent()).isEqualTo("CustomAgent/1.0");
            assertThat(found.getDetails()).isEqualTo("Assigned ADMIN role to user");
        }
    }
}
