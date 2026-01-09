package identityaccessmanagement.example.Identity.Access.Management.service;

import identityaccessmanagement.example.Identity.Access.Management.dto.UserResponseDto;
import identityaccessmanagement.example.Identity.Access.Management.mapper.UserMapper;
import identityaccessmanagement.example.Identity.Access.Management.model.User;
import identityaccessmanagement.example.Identity.Access.Management.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public UserService(UserRepository userRepository, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }

    public UserResponseDto getUserByUsername(String username) {
        User user = userRepository.findByUsernameWithRoles(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return userMapper.toResponse(user);
    }

    public UserResponseDto getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return userMapper.toResponse(user);
    }
}
