package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.service.AuthorizationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/v1/authorization")
public class AuthorizationController {

    private final AuthorizationService  authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @PostMapping("/users/{userId}/roles/{roleName}")
    public ResponseEntity<Void> assignRoleToUser(@PathVariable Long userId, @PathVariable String roleName) {
        authorizationService.assignRoleToUser(userId, roleName);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/users/{userId}/roles/{roleName}")
    public ResponseEntity<Void> RemoveRoleFromUser(@PathVariable Long userId, @PathVariable String roleName) {
        authorizationService.removeRoleFromUser(userId, roleName);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/users/{userId}/roles")
    public ResponseEntity<Set<String>> getUserRoles(@PathVariable Long userId) {
        return ResponseEntity.ok(authorizationService.getUserRoles(userId));
    }
}
