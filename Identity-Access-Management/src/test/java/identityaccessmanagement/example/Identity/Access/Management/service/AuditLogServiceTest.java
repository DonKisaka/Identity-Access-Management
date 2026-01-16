package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.dto.AuditLogResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.mapper.AuditLogMapper;
import identityaccessmanagement.example.Identity.Access.Management.model.AuditLog;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.AuditLogRepository;
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

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@DisplayName("AuditLogService Tests")
class AuditLogServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private AuditLogMapper auditLogMapper;

    @InjectMocks
    private AuditLogService auditLogService;

    @Captor
    private ArgumentCaptor<AuditLog> auditLogCaptor;

    private User testUser;
    private AuditLog testAuditLog;
    private AuditLogResponseDto testAuditLogResponse;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .build();

        testAuditLog = AuditLog.builder()
                .id(1L)
                .user(testUser)
                .action("LOGIN")
                .status("SUCCESS")
                .details("User logged in successfully")
                .ipAddress("192.168.1.1")
                .createdAt(LocalDateTime.now())
                .build();

        testAuditLogResponse = new AuditLogResponseDto(
                1L,
                "LOGIN",
                "SUCCESS",
                null,
                "192.168.1.1",
                LocalDateTime.now(),
                "testuser"
        );
    }

    @Nested
    @DisplayName("logEvent Tests")
    class LogEventTests {

        @Test
        @DisplayName("GIVEN valid event data WHEN logEvent is called THEN saves audit log")
        void shouldLogEventSuccessfully() {
            // GIVEN
            String action = "LOGIN";
            String status = "SUCCESS";
            String details = "User logged in from web";
            String ipAddress = "192.168.1.100";

            given(auditLogRepository.save(any(AuditLog.class))).willAnswer(invocation -> {
                AuditLog log = invocation.getArgument(0);
                log.setId(1L);
                return log;
            });

            // WHEN
            auditLogService.logEvent(testUser, action, status, details, ipAddress);

            // THEN - ArgumentCaptor to verify audit log was saved with correct data
            verify(auditLogRepository).save(auditLogCaptor.capture());
            AuditLog savedLog = auditLogCaptor.getValue();

            assertThat(savedLog.getUser()).isEqualTo(testUser);
            assertThat(savedLog.getAction()).isEqualTo(action);
            assertThat(savedLog.getStatus()).isEqualTo(status);
            assertThat(savedLog.getDetails()).isEqualTo(details);
            assertThat(savedLog.getIpAddress()).isEqualTo(ipAddress);
            assertThat(savedLog.getCreatedAt()).isNotNull();
        }

        @Test
        @DisplayName("GIVEN failed action WHEN logEvent is called THEN saves failure audit log")
        void shouldLogFailedEvent() {
            // GIVEN
            String action = "LOGIN";
            String status = "FAILURE";
            String details = "Invalid credentials provided";
            String ipAddress = "192.168.1.100";

            given(auditLogRepository.save(any(AuditLog.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            auditLogService.logEvent(testUser, action, status, details, ipAddress);

            // THEN
            verify(auditLogRepository).save(auditLogCaptor.capture());
            AuditLog savedLog = auditLogCaptor.getValue();

            assertThat(savedLog.getStatus()).isEqualTo("FAILURE");
            assertThat(savedLog.getDetails()).contains("Invalid credentials");
        }

        @Test
        @DisplayName("GIVEN different actions WHEN logEvent is called THEN logs each action correctly")
        void shouldLogDifferentActions() {
            // GIVEN
            given(auditLogRepository.save(any(AuditLog.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN - Log multiple different events
            auditLogService.logEvent(testUser, "LOGIN", "SUCCESS", "Login successful", "192.168.1.1");
            auditLogService.logEvent(testUser, "LOGOUT", "SUCCESS", "Logout successful", "192.168.1.1");
            auditLogService.logEvent(testUser, "PASSWORD_CHANGE", "SUCCESS", "Password changed", "192.168.1.1");

            // THEN - Verify all events were logged
            verify(auditLogRepository, times(3)).save(auditLogCaptor.capture());
            List<AuditLog> savedLogs = auditLogCaptor.getAllValues();

            assertThat(savedLogs).hasSize(3);
            assertThat(savedLogs).extracting(AuditLog::getAction)
                    .containsExactly("LOGIN", "LOGOUT", "PASSWORD_CHANGE");
        }

        @Test
        @DisplayName("GIVEN null details WHEN logEvent is called THEN saves log with null details")
        void shouldHandleNullDetails() {
            // GIVEN
            given(auditLogRepository.save(any(AuditLog.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            auditLogService.logEvent(testUser, "LOGIN", "SUCCESS", null, "192.168.1.1");

            // THEN
            verify(auditLogRepository).save(auditLogCaptor.capture());
            AuditLog savedLog = auditLogCaptor.getValue();

            assertThat(savedLog.getDetails()).isNull();
        }

        @Test
        @DisplayName("GIVEN event data WHEN logEvent is called THEN sets createdAt timestamp")
        void shouldSetCreatedAtTimestamp() {
            // GIVEN
            LocalDateTime beforeCall = LocalDateTime.now();
            given(auditLogRepository.save(any(AuditLog.class))).willAnswer(invocation -> invocation.getArgument(0));

            // WHEN
            auditLogService.logEvent(testUser, "LOGIN", "SUCCESS", "Details", "192.168.1.1");

            // THEN
            verify(auditLogRepository).save(auditLogCaptor.capture());
            AuditLog savedLog = auditLogCaptor.getValue();

            assertThat(savedLog.getCreatedAt()).isNotNull();
            assertThat(savedLog.getCreatedAt()).isAfterOrEqualTo(beforeCall);
        }
    }

    @Nested
    @DisplayName("getLogsByUser Tests")
    class GetLogsByUserTests {

        @Test
        @DisplayName("GIVEN user has audit logs WHEN getLogsByUser is called THEN returns paginated logs")
        void shouldReturnUserAuditLogs() {
            // GIVEN
            Long userId = 1L;
            Pageable pageable = PageRequest.of(0, 10);

            AuditLog log1 = AuditLog.builder()
                    .id(1L)
                    .user(testUser)
                    .action("LOGIN")
                    .status("SUCCESS")
                    .createdAt(LocalDateTime.now().minusHours(1))
                    .build();

            AuditLog log2 = AuditLog.builder()
                    .id(2L)
                    .user(testUser)
                    .action("LOGOUT")
                    .status("SUCCESS")
                    .createdAt(LocalDateTime.now())
                    .build();

            Page<AuditLog> logPage = new PageImpl<>(List.of(log1, log2), pageable, 2);

            AuditLogResponseDto response1 = new AuditLogResponseDto(1L, "LOGIN", "SUCCESS", null, null, LocalDateTime.now().minusHours(1), "testuser");
            AuditLogResponseDto response2 = new AuditLogResponseDto(2L, "LOGOUT", "SUCCESS", null, null, LocalDateTime.now(), "testuser");

            given(auditLogRepository.findByUserId(userId, pageable)).willReturn(logPage);
            given(auditLogMapper.toResponse(log1)).willReturn(response1);
            given(auditLogMapper.toResponse(log2)).willReturn(response2);

            // WHEN
            Page<AuditLogResponseDto> result = auditLogService.getLogsByUser(userId, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(2);
            assertThat(result.getTotalElements()).isEqualTo(2);
            assertThat(result.getContent()).extracting(AuditLogResponseDto::action)
                    .containsExactly("LOGIN", "LOGOUT");

            // Verification
            verify(auditLogRepository).findByUserId(userId, pageable);
            verify(auditLogMapper, times(2)).toResponse(any(AuditLog.class));
        }

        @Test
        @DisplayName("GIVEN user has no audit logs WHEN getLogsByUser is called THEN returns empty page")
        void shouldReturnEmptyPageWhenNoLogs() {
            // GIVEN
            Long userId = 1L;
            Pageable pageable = PageRequest.of(0, 10);
            Page<AuditLog> emptyPage = new PageImpl<>(List.of(), pageable, 0);

            given(auditLogRepository.findByUserId(userId, pageable)).willReturn(emptyPage);

            // WHEN
            Page<AuditLogResponseDto> result = auditLogService.getLogsByUser(userId, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
            assertThat(result.getTotalElements()).isZero();

            verify(auditLogMapper, never()).toResponse(any());
        }

        @Test
        @DisplayName("GIVEN paginated request WHEN getLogsByUser is called THEN respects pagination")
        void shouldRespectPagination() {
            // GIVEN
            Long userId = 1L;
            Pageable pageable = PageRequest.of(1, 5); // Second page, 5 items per page

            Page<AuditLog> logPage = new PageImpl<>(List.of(testAuditLog), pageable, 10);
            given(auditLogRepository.findByUserId(userId, pageable)).willReturn(logPage);
            given(auditLogMapper.toResponse(testAuditLog)).willReturn(testAuditLogResponse);

            // WHEN
            Page<AuditLogResponseDto> result = auditLogService.getLogsByUser(userId, pageable);

            // THEN
            assertThat(result.getNumber()).isEqualTo(1); // Page number
            assertThat(result.getSize()).isEqualTo(5); // Page size
            assertThat(result.getTotalElements()).isEqualTo(10); // Total elements
        }
    }

    @Nested
    @DisplayName("getLogsByDateRange Tests")
    class GetLogsByDateRangeTests {

        @Test
        @DisplayName("GIVEN date range with logs WHEN getLogsByDateRange is called THEN returns logs within range")
        void shouldReturnLogsWithinDateRange() {
            // GIVEN
            LocalDateTime start = LocalDateTime.now().minusDays(7);
            LocalDateTime end = LocalDateTime.now();
            Pageable pageable = PageRequest.of(0, 10);

            AuditLog log1 = AuditLog.builder()
                    .id(1L)
                    .user(testUser)
                    .action("LOGIN")
                    .createdAt(LocalDateTime.now().minusDays(3))
                    .build();

            AuditLog log2 = AuditLog.builder()
                    .id(2L)
                    .user(testUser)
                    .action("PASSWORD_CHANGE")
                    .createdAt(LocalDateTime.now().minusDays(1))
                    .build();

            Page<AuditLog> logPage = new PageImpl<>(List.of(log1, log2), pageable, 2);

            AuditLogResponseDto response1 = new AuditLogResponseDto(1L, "LOGIN", null, null, null, LocalDateTime.now().minusDays(3), "testuser");
            AuditLogResponseDto response2 = new AuditLogResponseDto(2L, "PASSWORD_CHANGE", null, null, null, LocalDateTime.now().minusDays(1), "testuser");

            given(auditLogRepository.findByCreatedAtBetween(start, end, pageable)).willReturn(logPage);
            given(auditLogMapper.toResponse(log1)).willReturn(response1);
            given(auditLogMapper.toResponse(log2)).willReturn(response2);

            // WHEN
            Page<AuditLogResponseDto> result = auditLogService.getLogsByDateRange(start, end, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).hasSize(2);
            assertThat(result.getContent()).extracting(AuditLogResponseDto::action)
                    .containsExactly("LOGIN", "PASSWORD_CHANGE");

            // Verification
            verify(auditLogRepository).findByCreatedAtBetween(start, end, pageable);
        }

        @Test
        @DisplayName("GIVEN date range with no logs WHEN getLogsByDateRange is called THEN returns empty page")
        void shouldReturnEmptyPageWhenNoLogsInRange() {
            // GIVEN
            LocalDateTime start = LocalDateTime.now().minusYears(10);
            LocalDateTime end = LocalDateTime.now().minusYears(9);
            Pageable pageable = PageRequest.of(0, 10);
            Page<AuditLog> emptyPage = new PageImpl<>(List.of(), pageable, 0);

            given(auditLogRepository.findByCreatedAtBetween(start, end, pageable)).willReturn(emptyPage);

            // WHEN
            Page<AuditLogResponseDto> result = auditLogService.getLogsByDateRange(start, end, pageable);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.getContent()).isEmpty();
            assertThat(result.getTotalElements()).isZero();
        }

        @Test
        @DisplayName("GIVEN same start and end date WHEN getLogsByDateRange is called THEN searches that specific day")
        void shouldSearchSingleDay() {
            // GIVEN
            LocalDateTime singleDay = LocalDateTime.of(2024, 1, 15, 0, 0);
            Pageable pageable = PageRequest.of(0, 10);
            Page<AuditLog> emptyPage = new PageImpl<>(List.of(), pageable, 0);

            given(auditLogRepository.findByCreatedAtBetween(singleDay, singleDay, pageable)).willReturn(emptyPage);

            // WHEN
            auditLogService.getLogsByDateRange(singleDay, singleDay, pageable);

            // THEN
            verify(auditLogRepository).findByCreatedAtBetween(eq(singleDay), eq(singleDay), eq(pageable));
        }

        @Test
        @DisplayName("GIVEN large date range WHEN getLogsByDateRange is called THEN correctly paginates results")
        void shouldPaginateLargeDateRange() {
            // GIVEN
            LocalDateTime start = LocalDateTime.now().minusYears(1);
            LocalDateTime end = LocalDateTime.now();
            Pageable pageable = PageRequest.of(0, 100);

            Page<AuditLog> logPage = new PageImpl<>(List.of(testAuditLog), pageable, 500); // 500 total logs

            given(auditLogRepository.findByCreatedAtBetween(start, end, pageable)).willReturn(logPage);
            given(auditLogMapper.toResponse(testAuditLog)).willReturn(testAuditLogResponse);

            // WHEN
            Page<AuditLogResponseDto> result = auditLogService.getLogsByDateRange(start, end, pageable);

            // THEN
            assertThat(result.getTotalElements()).isEqualTo(500);
            assertThat(result.getTotalPages()).isEqualTo(5); // 500 / 100 = 5 pages
        }
    }
}
