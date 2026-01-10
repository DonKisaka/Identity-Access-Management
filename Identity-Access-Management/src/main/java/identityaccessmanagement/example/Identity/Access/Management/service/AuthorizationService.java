package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.model.Role;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.RoleRepository;
import identityaccessmanagement.example.Identity.Access.Management.repository.UserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthorizationService {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;

    public AuthorizationService(RoleRepository roleRepository, UserRepository userRepository) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void assignRoleToUser(Long userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));
        user.getRoles().add(role);
        userRepository.save(user);
    }
}
