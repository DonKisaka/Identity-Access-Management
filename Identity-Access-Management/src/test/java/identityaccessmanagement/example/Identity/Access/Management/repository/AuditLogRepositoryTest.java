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
@DisplayName("AuditLogRepository Tests")
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
        // Note: @PrePersist sets createdAt to now(), so all logs will have current timestamp
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
    @DisplayName("findByUserId Tests")
    class FindByUserIdTests {

        @Test
        @DisplayName("GIVEN user has audit logs WHEN findByUserId is called THEN returns paginated logs")
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
        @DisplayName("GIVEN user has no audit logs WHEN findByUserId is called THEN returns empty page")
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
        @DisplayName("GIVEN pagination WHEN findByUserId is called THEN respects page size")
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
        @DisplayName("GIVEN second page requested WHEN findByUserId is called THEN returns correct page")
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
    @DisplayName("findByActionAndStatus Tests")
    class FindByActionAndStatusTests {

        @Test
        @DisplayName("GIVEN logs with action and status WHEN findByActionAndStatus is called THEN returns matching logs")
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
        @DisplayName("GIVEN logs with failed status WHEN findByActionAndStatus is called THEN returns failed logs")
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
        @DisplayName("GIVEN no matching logs WHEN findByActionAndStatus is called THEN returns empty page")
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
        @DisplayName("GIVEN logout action WHEN findByActionAndStatus is called THEN returns logout logs")
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
    @DisplayName("findByCreatedAtBetween Tests")
    class FindByCreatedAtBetweenTests {

        @Test
        @DisplayName("GIVEN logs in date range WHEN findByCreatedAtBetween is called THEN returns logs in range")
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
        @DisplayName("GIVEN current time range WHEN findByCreatedAtBetween is called THEN returns all recent logs")
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
        @DisplayName("GIVEN no logs in date range WHEN findByCreatedAtBetween is called THEN returns empty page")
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
        @DisplayName("GIVEN past date range WHEN findByCreatedAtBetween is called THEN returns empty page")
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
    @DisplayName("CRUD Operations Tests")
    class CrudOperationsTests {

        @Test
        @DisplayName("GIVEN new audit log WHEN save is called THEN log is persisted")
        void shouldSaveNewAuditLog() {
            // GIVEN
            AuditLog newLog = AuditLog.builder()
                    .user(testUser)
                    .action("PASSWORD_CHANGE")
                    .status("SUCCESS")
                    .details("User changed password")
                    .ipAddress("192.168.1.1")
                    .createdAt(LocalDateTime.now())
                    .build();

            // WHEN
            AuditLog savedLog = auditLogRepository.save(newLog);

            // THEN
            assertThat(savedLog.getId()).isNotNull();
            assertThat(savedLog.getAction()).isEqualTo("PASSWORD_CHANGE");
        }

        @Test
        @DisplayName("GIVEN audit log WHEN delete is called THEN log is removed")
        void shouldDeleteAuditLog() {
            // GIVEN
            Long logId = loginLog.getId();
            assertThat(auditLogRepository.findById(logId)).isPresent();

            // WHEN
            auditLogRepository.deleteById(logId);

            // THEN
            assertThat(auditLogRepository.findById(logId)).isEmpty();
        }

        @Test
        @DisplayName("GIVEN multiple logs WHEN count is called THEN returns correct count")
        void shouldCountLogs() {
            // GIVEN - 4 logs persisted in setUp

            // WHEN
            long count = auditLogRepository.count();

            // THEN
            assertThat(count).isGreaterThanOrEqualTo(4);
        }
    }

    @Nested
    @DisplayName("Audit Log Metadata Tests")
    class AuditLogMetadataTests {

        @Test
        @DisplayName("GIVEN audit log with all fields WHEN save and find THEN all fields are preserved")
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
