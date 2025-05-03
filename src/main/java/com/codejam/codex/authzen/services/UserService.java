package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserResponse loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        if (!StringUtils.hasText(usernameOrEmail)) {
            throw new UsernameNotFoundException("Username/email cannot be empty");
        }

        try {
            User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with username/email: " + usernameOrEmail));

            if (!user.isActive()) {
                throw new UsernameNotFoundException("User account is not active");
            }

            if (user.isLocked()) {
                throw new UsernameNotFoundException("User account is locked");
            }

            Set<String> roles = user.getUserRoles()
                    .stream()
                    .map(userRole -> userRole.getRole().getName())
                    .collect(Collectors.toSet());

            List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());

            return UserResponse.builder()
                    .id(user.getId())
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .roles(roles)
                    .permissions(permissionNames)
                    .build();
        } catch (UsernameNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new UsernameNotFoundException("Error loading user: " + e.getMessage());
        }
    }

    public UserResponse getProfile(String username) {
        if (!StringUtils.hasText(username)) {
            throw new RuntimeException("Username cannot be empty");
        }

        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
            
            if (!user.isActive()) {
                throw new RuntimeException("User account is not active");
            }

            if (user.isLocked()) {
                throw new RuntimeException("User account is locked");
            }

            List<String> permissionNames = userRepository.findPermissionNamesByUsername(username);
            return UserResponse.fromEntity(user, permissionNames);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error getting user profile: " + e.getMessage());
        }
    }

    @Transactional
    public UpdateUserResponse updateUser(String username, UpdateUserRequest updateRequest) {
        if (!StringUtils.hasText(username)) {
            throw new RuntimeException("Username cannot be empty");
        }

        if (updateRequest == null) {
            throw new RuntimeException("Update request cannot be null");
        }

        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found with username: " + username));

            if (!user.isActive()) {
                throw new RuntimeException("Cannot update inactive user account");
            }

            if (user.isLocked()) {
                throw new RuntimeException("Cannot update locked user account");
            }

            if (updateRequest.getUsername() != null && !updateRequest.getUsername().isBlank()) {
                if (!updateRequest.getUsername().equals(username) && 
                    userRepository.existsByUsername(updateRequest.getUsername())) {
                    throw new RuntimeException("Username already exists");
                }
                user.setUsername(updateRequest.getUsername());
            }

            if (updateRequest.getEmail() != null && !updateRequest.getEmail().isBlank()) {
                if (!updateRequest.getEmail().equals(user.getEmail()) && 
                    userRepository.existsByEmail(updateRequest.getEmail())) {
                    throw new RuntimeException("Email already exists");
                }
                user.setEmail(updateRequest.getEmail());
            }

            if (updateRequest.getPassword() != null && !updateRequest.getPassword().isBlank()) {
                if (updateRequest.getPassword().length() < 8) {
                    throw new RuntimeException("Password must be at least 8 characters long");
                }
                user.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
                user.setPasswordChangedAt(new java.sql.Timestamp(System.currentTimeMillis()));
            }

            User updatedUser = userRepository.save(user);
            return UpdateUserResponse.fromEntity(updatedUser);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error updating user: " + e.getMessage());
        }
    }
}
