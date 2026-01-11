package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.UserResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getCurrentUser(
            Authentication authentication
    ) {
        UserResponseDto user = userService.getUserByUsername(authentication.getName());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/{username}")
    public ResponseEntity<UserResponseDto> getUserByUsername(@PathVariable String username) {
        UserResponseDto user = userService.getUserByUsername(username);
        return ResponseEntity.ok(user);
    }

    @GetMapping()
    public ResponseEntity<Page<UserResponseDto>> getAllUsers(Pageable pageable) {
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }

    @PostMapping("/{userId}/unlock")
    public ResponseEntity<Void> unlockUser(@PathVariable Long userId) {
        userService.unlockUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{userId}/disable")
    public ResponseEntity<Void> disableUser(@PathVariable Long userId) {
        userService.disableUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{userId}/enable")
    public ResponseEntity<Void> enableUser(@PathVariable Long userId) {
        userService.enableUser(userId);
        return ResponseEntity.ok().build();
    }
}
