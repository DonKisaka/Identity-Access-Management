package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionRequestDto;
import identityaccessmanagement.example.Identity.Access.Management.dto.PermissionResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.exception.DuplicateResourceException;
import identityaccessmanagement.example.Identity.Access.Management.mapper.PermissionMapper;
import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.repository.PermissionRepository;
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

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private PermissionMapper permissionMapper;

    @InjectMocks
    private PermissionService permissionService;

    @Captor
    private ArgumentCaptor<Permission> permissionCaptor;

    private Permission readPermission;
    private Permission writePermission;
    private PermissionResponseDto readPermissionResponse;
    private PermissionResponseDto writePermissionResponse;

    @BeforeEach
    void setUp() {
        readPermission = Permission.builder()
                .id(1L)
                .name("READ_USERS")
                .resource("users")
                .action("read")
                .description("Read users permission")
                .build();

        writePermission = Permission.builder()
                .id(2L)
                .name("WRITE_USERS")
                .resource("users")
                .action("write")
                .description("Write users permission")
                .build();

        readPermissionResponse = new PermissionResponseDto(1L, "READ_USERS", "read", "users", "Read users permission");
        writePermissionResponse = new PermissionResponseDto(2L, "WRITE_USERS", "write", "users", "Write users permission");
    }

    @Nested
    class GetAllPermissionsTests {

        @Test
        void shouldReturnAllPermissions() {
            // GIVEN
            given(permissionRepository.findAll()).willReturn(List.of(readPermission, writePermission));
            given(permissionMapper.toResponse(readPermission)).willReturn(readPermissionResponse);
            given(permissionMapper.toResponse(writePermission)).willReturn(writePermissionResponse);

            // WHEN
            List<PermissionResponseDto> result = permissionService.getAllPermissions();

            // THEN
            assertThat(result).hasSize(2);
            assertThat(result).extracting(PermissionResponseDto::name)
                    .containsExactlyInAnyOrder("READ_USERS", "WRITE_USERS");

            // Verification
            verify(permissionRepository, times(1)).findAll();
            verify(permissionMapper, times(2)).toResponse(any(Permission.class));
        }

        @Test
        void shouldReturnEmptyListWhenNoPermissions() {
            // GIVEN
            given(permissionRepository.findAll()).willReturn(List.of());

            // WHEN
            List<PermissionResponseDto> result = permissionService.getAllPermissions();

            // THEN
            assertThat(result).isEmpty();

            verify(permissionRepository).findAll();
            verify(permissionMapper, never()).toResponse(any());
        }

        @Test
        void shouldPreserveAllPermissionDetails() {
            // GIVEN
            Permission detailedPermission = Permission.builder()
                    .id(3L)
                    .name("DELETE_USERS")
                    .resource("users")
                    .action("delete")
                    .description("Delete users permission")
                    .build();
            PermissionResponseDto detailedResponse = new PermissionResponseDto(
                    3L, "DELETE_USERS", "delete", "users", "Delete users permission"
            );

            given(permissionRepository.findAll()).willReturn(List.of(detailedPermission));
            given(permissionMapper.toResponse(detailedPermission)).willReturn(detailedResponse);

            // WHEN
            List<PermissionResponseDto> result = permissionService.getAllPermissions();

            // THEN
            assertThat(result).hasSize(1);
            PermissionResponseDto permission = result.get(0);
            assertThat(permission.id()).isEqualTo(3L);
            assertThat(permission.name()).isEqualTo("DELETE_USERS");
            assertThat(permission.resource()).isEqualTo("users");
            assertThat(permission.action()).isEqualTo("delete");
            assertThat(permission.description()).isEqualTo("Delete users permission");
        }
    }

    @Nested
    class CreatePermissionTests {

        @Test
        @DisplayName("GIVEN a valid permission request WHEN createPermission is called THEN creates and returns the permission")
        void shouldCreatePermissionSuccessfully() {
            // GIVEN
            PermissionRequestDto requestDto = new PermissionRequestDto(
                    "UPDATE_USERS", "users", "update", "Update users permission"
            );
            PermissionResponseDto expectedResponse = new PermissionResponseDto(
                    3L, "UPDATE_USERS", "update", "users", "Update users permission"
            );

            given(permissionRepository.findByName("UPDATE_USERS")).willReturn(Optional.empty());
            given(permissionRepository.save(any(Permission.class))).willAnswer(invocation -> {
                Permission savedPermission = invocation.getArgument(0);
                savedPermission.setId(3L);
                return savedPermission;
            });
            given(permissionMapper.toResponse(any(Permission.class))).willReturn(expectedResponse);

            // WHEN
            PermissionResponseDto result = permissionService.createPermission(requestDto);

            // THEN
            assertThat(result).isNotNull();
            assertThat(result.name()).isEqualTo("UPDATE_USERS");
            assertThat(result.resource()).isEqualTo("users");
            assertThat(result.action()).isEqualTo("update");

            // ArgumentCaptor to verify saved permission
            verify(permissionRepository).save(permissionCaptor.capture());
            Permission capturedPermission = permissionCaptor.getValue();
            assertThat(capturedPermission.getName()).isEqualTo("UPDATE_USERS");
            assertThat(capturedPermission.getResource()).isEqualTo("users");
            assertThat(capturedPermission.getAction()).isEqualTo("update");
            assertThat(capturedPermission.getDescription()).isEqualTo("Update users permission");
        }

        @Test
        void shouldThrowExceptionWhenPermissionAlreadyExists() {
            // GIVEN
            PermissionRequestDto requestDto = new PermissionRequestDto(
                    "READ_USERS", "users", "read", "Duplicate permission"
            );
            given(permissionRepository.findByName("READ_USERS")).willReturn(Optional.of(readPermission));

            // WHEN/THEN - Exception Testing
            assertThatThrownBy(() -> permissionService.createPermission(requestDto))
                    .isInstanceOf(DuplicateResourceException.class)
                    .hasMessageContaining("Permission")
                    .hasMessageContaining("name")
                    .hasMessageContaining("READ_USERS");

            // Verification: save should never be called when duplicate exists
            verify(permissionRepository, never()).save(any());
        }

        @Test
        void shouldCreatePermissionWithNullDescription() {
            // GIVEN
            PermissionRequestDto requestDto = new PermissionRequestDto(
                    "BASIC_ACCESS", "basic", "access", null
            );
            PermissionResponseDto expectedResponse = new PermissionResponseDto(
                    4L, "BASIC_ACCESS", "access", "basic", null
            );

            given(permissionRepository.findByName("BASIC_ACCESS")).willReturn(Optional.empty());
            given(permissionRepository.save(any(Permission.class))).willAnswer(invocation -> {
                Permission savedPermission = invocation.getArgument(0);
                savedPermission.setId(4L);
                return savedPermission;
            });
            given(permissionMapper.toResponse(any(Permission.class))).willReturn(expectedResponse);

            // WHEN
            permissionService.createPermission(requestDto);

            // THEN
            verify(permissionRepository).save(permissionCaptor.capture());
            Permission capturedPermission = permissionCaptor.getValue();

            assertThat(capturedPermission.getName()).isEqualTo("BASIC_ACCESS");
            assertThat(capturedPermission.getResource()).isEqualTo("basic");
            assertThat(capturedPermission.getAction()).isEqualTo("access");
            assertThat(capturedPermission.getDescription()).isNull();
        }

        @Test
        void shouldPropagateExceptionWhenSaveFails() {
            // GIVEN
            PermissionRequestDto requestDto = new PermissionRequestDto(
                    "NEW_PERMISSION", "resource", "action", "description"
            );

            given(permissionRepository.findByName("NEW_PERMISSION")).willReturn(Optional.empty());
            given(permissionRepository.save(any(Permission.class)))
                    .willThrow(new RuntimeException("Database connection error"));

            // WHEN/THEN
            assertThatThrownBy(() -> permissionService.createPermission(requestDto))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Database connection error");

            verify(permissionMapper, never()).toResponse(any());
        }
    }

    @Nested
    class PermissionCreationEdgeCases {

        @Test
        @DisplayName("GIVEN permission with special characters in name WHEN createPermission is called THEN creates permission successfully")
        void shouldHandleSpecialCharactersInName() {
            // GIVEN
            PermissionRequestDto requestDto = new PermissionRequestDto(
                    "RESOURCE:ACTION:SCOPE", "resource", "action", "Complex permission"
            );
            PermissionResponseDto expectedResponse = new PermissionResponseDto(
                    5L, "RESOURCE:ACTION:SCOPE", "action", "resource", "Complex permission"
            );

            given(permissionRepository.findByName("RESOURCE:ACTION:SCOPE")).willReturn(Optional.empty());
            given(permissionRepository.save(any(Permission.class))).willAnswer(invocation -> {
                Permission savedPermission = invocation.getArgument(0);
                savedPermission.setId(5L);
                return savedPermission;
            });
            given(permissionMapper.toResponse(any(Permission.class))).willReturn(expectedResponse);

            // WHEN
            PermissionResponseDto result = permissionService.createPermission(requestDto);

            // THEN
            assertThat(result.name()).isEqualTo("RESOURCE:ACTION:SCOPE");
        }

        @Test
        void shouldVerifyCorrectInteractionOrder() {
            // GIVEN
            PermissionRequestDto requestDto = new PermissionRequestDto(
                    "ORDERED_PERMISSION", "resource", "action", "Test ordering"
            );
            PermissionResponseDto expectedResponse = new PermissionResponseDto(
                    6L, "ORDERED_PERMISSION", "action", "resource", "Test ordering"
            );

            given(permissionRepository.findByName("ORDERED_PERMISSION")).willReturn(Optional.empty());
            given(permissionRepository.save(any(Permission.class))).willAnswer(invocation -> {
                Permission savedPermission = invocation.getArgument(0);
                savedPermission.setId(6L);
                return savedPermission;
            });
            given(permissionMapper.toResponse(any(Permission.class))).willReturn(expectedResponse);

            // WHEN
            permissionService.createPermission(requestDto);

            // THEN - Verification of interaction order
            var inOrder = inOrder(permissionRepository, permissionMapper);
            inOrder.verify(permissionRepository).findByName("ORDERED_PERMISSION");
            inOrder.verify(permissionRepository).save(any(Permission.class));
            inOrder.verify(permissionMapper).toResponse(any(Permission.class));
        }
    }
}
