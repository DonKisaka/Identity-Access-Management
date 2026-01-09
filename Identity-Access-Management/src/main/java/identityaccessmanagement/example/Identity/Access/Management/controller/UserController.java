package identityaccessmanagement.example.Identity.Access.Management.controller;

import identityaccessmanagement.example.Identity.Access.Management.dto.UserResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
