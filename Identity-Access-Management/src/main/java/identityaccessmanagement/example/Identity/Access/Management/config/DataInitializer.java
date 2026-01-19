package identityaccessmanagement.example.Identity.Access.Management.config;

import identityaccessmanagement.example.Identity.Access.Management.model.Permission;
import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.PermissionRepository;
import identityaccessmanagement.example.Identity.Access.Management.repository.RoleRepository;
import identityaccessmanagement.example.Identity.Access.Management.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


@Component
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class DataInitializer implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final Map<String, String[]> PERMISSION_DEFINITIONS = Map.ofEntries(
            // User permissions
            Map.entry("users:read", new String[]{"users", "read", "View user profiles and list users"}),
            Map.entry("users:create", new String[]{"users", "create", "Create new user accounts"}),
            Map.entry("users:update", new String[]{"users", "update", "Update user information"}),
            Map.entry("users:delete", new String[]{"users", "delete", "Delete user accounts"}),
            Map.entry("users:manage", new String[]{"users", "manage", "Full user management including lock/unlock"}),

            // Role permissions
            Map.entry("roles:read", new String[]{"roles", "read", "View roles and their permissions"}),
            Map.entry("roles:create", new String[]{"roles", "create", "Create new roles"}),
            Map.entry("roles:update", new String[]{"roles", "update", "Update role information and permissions"}),
            Map.entry("roles:delete", new String[]{"roles", "delete", "Delete roles"}),
            Map.entry("roles:assign", new String[]{"roles", "assign", "Assign roles to users"}),

            // Permission permissions
            Map.entry("permissions:read", new String[]{"permissions", "read", "View available permissions"}),
            Map.entry("permissions:create", new String[]{"permissions", "create", "Create new permissions"}),
            Map.entry("permissions:update", new String[]{"permissions", "update", "Update permission definitions"}),
            Map.entry("permissions:delete", new String[]{"permissions", "delete", "Delete permissions"}),

            // Audit permissions
            Map.entry("audit:read", new String[]{"audit_logs", "read", "View audit logs"}),
            Map.entry("audit:export", new String[]{"audit_logs", "export", "Export audit logs"}),
            Map.entry("audit:delete", new String[]{"audit_logs", "delete", "Delete audit log entries"}),

            // System permissions
            Map.entry("system:settings", new String[]{"system", "settings", "Manage system settings"}),
            Map.entry("system:monitor", new String[]{"system", "monitor", "Access system monitoring and health"}),
            Map.entry("system:backup", new String[]{"system", "backup", "Perform system backups"}),

            // Profile permissions (self-service)
            Map.entry("profile:read", new String[]{"profile", "read", "View own profile"}),
            Map.entry("profile:update", new String[]{"profile", "update", "Update own profile information"}),
            Map.entry("profile:password", new String[]{"profile", "password", "Change own password"})
    );

    private static final Map<String, RoleDefinition> ROLE_DEFINITIONS = Map.of(
            "USER", new RoleDefinition(
                    "Standard user with basic access",
                    List.of("profile:read", "profile:update", "profile:password", "users:read")
            ),
            "MODERATOR", new RoleDefinition(
                    "Moderator with user oversight capabilities",
                    List.of("profile:read", "profile:update", "profile:password",
                            "users:read", "users:update",
                            "audit:read")
            ),
            "MANAGER", new RoleDefinition(
                    "Manager with team and user management capabilities",
                    List.of("profile:read", "profile:update", "profile:password",
                            "users:read", "users:create", "users:update", "users:manage",
                            "roles:read", "roles:assign",
                            "permissions:read",
                            "audit:read", "audit:export")
            ),
            "ADMIN", new RoleDefinition(
                    "Administrator with full system access",
                    List.of("profile:read", "profile:update", "profile:password",
                            "users:read", "users:create", "users:update", "users:delete", "users:manage",
                            "roles:read", "roles:create", "roles:update", "roles:delete", "roles:assign",
                            "permissions:read", "permissions:create", "permissions:update", "permissions:delete",
                            "audit:read", "audit:export", "audit:delete",
                            "system:settings", "system:monitor", "system:backup")
            ),
            "SUPER_ADMIN", new RoleDefinition(
                    "Super administrator with unrestricted access",
                    List.of() // Will receive ALL permissions
            )
    );

    private record RoleDefinition(String description, List<String> permissions) {}

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        log.info("Starting data initialization...");

        Map<String, Permission> permissionMap = initializePermissions();
        initializeRoles(permissionMap);
        initializeDefaultUsers();

        log.info("Data initialization completed successfully.");
    }

    private Map<String, Permission> initializePermissions() {
        Map<String, Permission> permissionMap = new HashMap<>();

        permissionRepository.findAll().forEach(p -> permissionMap.put(p.getName(), p));

        if (permissionMap.isEmpty()) {
            log.info("Creating {} default permissions...", PERMISSION_DEFINITIONS.size());

            PERMISSION_DEFINITIONS.forEach((name, details) -> {
                Permission permission = Permission.builder()
                        .name(name)
                        .resource(details[0])
                        .action(details[1])
                        .description(details[2])
                        .build();
                Permission saved = permissionRepository.save(permission);
                permissionMap.put(name, saved);
                log.debug("Created permission: {}", name);
            });

            log.info("Successfully created {} permissions.", permissionMap.size());
        } else {
            log.info("Found {} existing permissions, checking for missing ones...", permissionMap.size());

            PERMISSION_DEFINITIONS.forEach((name, details) -> {
                if (!permissionMap.containsKey(name)) {
                    Permission permission = Permission.builder()
                            .name(name)
                            .resource(details[0])
                            .action(details[1])
                            .description(details[2])
                            .build();
                    Permission saved = permissionRepository.save(permission);
                    permissionMap.put(name, saved);
                    log.info("Added missing permission: {}", name);
                }
            });
        }

        return permissionMap;
    }

    private void initializeRoles(Map<String, Permission> permissionMap) {
        Map<String, Role> existingRoles = roleRepository.findAll().stream()
                .collect(Collectors.toMap(Role::getName, r -> r));

        if (existingRoles.isEmpty()) {
            log.info("Creating {} default roles...", ROLE_DEFINITIONS.size());

            ROLE_DEFINITIONS.forEach((name, definition) -> {
                Set<Permission> rolePermissions = resolvePermissions(name, definition, permissionMap);

                Role role = Role.builder()
                        .name(name)
                        .description(definition.description())
                        .permissions(rolePermissions)
                        .build();

                roleRepository.save(role);
                log.info("Created role: {} with {} permissions", name, rolePermissions.size());
            });
        } else {
            log.info("Found {} existing roles, checking for missing ones...", existingRoles.size());

            ROLE_DEFINITIONS.forEach((name, definition) -> {
                if (!existingRoles.containsKey(name)) {
                    Set<Permission> rolePermissions = resolvePermissions(name, definition, permissionMap);

                    Role role = Role.builder()
                            .name(name)
                            .description(definition.description())
                            .permissions(rolePermissions)
                            .build();

                    roleRepository.save(role);
                    log.info("Added missing role: {} with {} permissions", name, rolePermissions.size());
                }
            });
        }
    }

    private Set<Permission> resolvePermissions(String roleName, RoleDefinition definition,
                                                Map<String, Permission> permissionMap) {
        // SUPER_ADMIN gets all permissions
        if ("SUPER_ADMIN".equals(roleName)) {
            return new HashSet<>(permissionMap.values());
        }

        Set<Permission> permissions = new HashSet<>();
        for (String permName : definition.permissions()) {
            Permission perm = permissionMap.get(permName);
            if (perm != null) {
                permissions.add(perm);
            } else {
                log.warn("Permission '{}' not found for role '{}'", permName, roleName);
            }
        }
        return permissions;
    }

    private void initializeDefaultUsers() {
        if (userRepository.count() > 0) {
            log.info("Users already exist, skipping default user creation.");
            return;
        }

        log.info("Creating default users...");

        // Create Super Admin
        createUser("superadmin", "superadmin@system.local", "SuperAdmin@123!", "SUPER_ADMIN");

        // Create Admin
        createUser("admin", "admin@system.local", "Admin@123!", "ADMIN");

        // Create Manager
        createUser("manager", "manager@system.local", "Manager@123!", "MANAGER");

        // Create Moderator
        createUser("moderator", "moderator@system.local", "Moderator@123!", "MODERATOR");

        log.info("=========================================");
        log.info("DEFAULT USERS CREATED:");
        log.info("-----------------------------------------");
        log.info("| Username    | Password        | Role       |");
        log.info("-----------------------------------------");
        log.info("| superadmin  | SuperAdmin@123! | SUPER_ADMIN|");
        log.info("| admin       | Admin@123!      | ADMIN      |");
        log.info("| manager     | Manager@123!    | MANAGER    |");
        log.info("| moderator   | Moderator@123!  | MODERATOR  |");
        log.info("-----------------------------------------");
        log.warn(">>> CHANGE THESE PASSWORDS IMMEDIATELY IN PRODUCTION! <<<");
        log.info("=========================================");
    }

    private void createUser(String username, String email, String password, String roleName) {
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new IllegalStateException("Role not found: " + roleName));

        Set<Role> roles = new HashSet<>();
        roles.add(role);

        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .enabled(true)
                .isLocked(false)
                .failedLoginAttempts(0)
                .roles(roles)
                .build();

        userRepository.save(user);
        log.debug("Created user: {} with role: {}", username, roleName);
    }
}
